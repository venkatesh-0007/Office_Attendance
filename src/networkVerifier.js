const os = require('node:os');
const https = require('node:https');
const ipaddr = require('ipaddr.js');
const dbHelpers = require('./db');

let cachedPublicIp = null;
let lastPublicIpFetch = 0;
const CACHE_TTL_MS = 10000;

/**
 * Clean, sanitize and validate an IP address string.
 */
function normalizeIp(ipString) {
  if (!ipString) return '127.0.0.1';
  let cleaned = String(ipString).trim();

  // If comma-separated, take the leftmost valid IP (or rightmost depending on proxy)
  if (cleaned.includes(',')) {
    const parts = cleaned.split(',').map(s => s.trim());
    cleaned = parts[0];
  }

  // Remove port if present
  if (cleaned.startsWith('[') && cleaned.includes(']')) {
    cleaned = cleaned.slice(1, cleaned.indexOf(']'));
  } else if (cleaned.includes(':') && cleaned.split(':').length === 2 && !cleaned.includes('::')) {
    cleaned = cleaned.split(':')[0];
  }

  try {
    let parsed = ipaddr.parse(cleaned);
    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
      return parsed.toIPv4Address().toString();
    }
    return parsed.toString();
  } catch (err) {
    return cleaned;
  }
}

/**
 * Safely extract connecting client IP without blindly trusting client headers.
 * - On Vercel: x-real-ip is guaranteed by Vercel edge.
 * - On Cloudflare: cf-connecting-ip is authoritative.
 * - Otherwise: uses Express validated req.ip or socket remote address.
 */
function getClientIp(req) {
  // During automated unit/integration tests only, support x-test-ip
  if (process.env.NODE_ENV === 'test' && req.headers['x-test-ip']) {
    return normalizeIp(req.headers['x-test-ip']);
  }

  let rawIp = null;

  // On Vercel: Vercel edge sets x-real-ip and x-vercel-forwarded-for
  if (process.env.VERCEL || req.headers['x-vercel-id']) {
    rawIp = req.headers['x-real-ip'] || req.headers['x-vercel-forwarded-for'];
  } else if (process.env.TRUST_CLOUDFLARE && req.headers['cf-connecting-ip']) {
    rawIp = req.headers['cf-connecting-ip'];
  } else if (req.ip) {
    // Standard Express proxy trust (app.set('trust proxy', 1))
    rawIp = req.ip;
  } else {
    rawIp = req.socket?.remoteAddress;
  }

  return normalizeIp(rawIp || '127.0.0.1');
}

/**
 * Get machine's active local interfaces (for local dev server).
 */
function getLocalInterfaces() {
  const nets = os.networkInterfaces();
  const results = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (!net.internal && (net.family === 'IPv4' || net.family === 4)) {
        let prefix = 24;
        try {
          const bits = net.netmask.split('.').map(Number).map(n => n.toString(2).padStart(8, '0')).join('');
          prefix = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
        } catch (e) {}

        const parts = net.address.split('.');
        const subnetBase = `${parts[0]}.${parts[1]}.${parts[2]}.0/${prefix}`;

        results.push({
          interface: name,
          ip: net.address,
          netmask: net.netmask,
          subnet: subnetBase
        });
      }
    }
  }
  return results;
}

/**
 * Resolve current public WAN IP of the network.
 */
function fetchPublicIp() {
  const now = Date.now();
  if (cachedPublicIp && (now - lastPublicIpFetch) < CACHE_TTL_MS) {
    return Promise.resolve(cachedPublicIp);
  }

  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org?format=json', { timeout: 2500 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed && parsed.ip) {
            cachedPublicIp = parsed.ip.trim();
            lastPublicIpFetch = Date.now();
          }
          resolve(cachedPublicIp);
        } catch (e) {
          resolve(cachedPublicIp);
        }
      });
    });

    req.on('error', () => resolve(cachedPublicIp));
    req.on('timeout', () => {
      req.destroy();
      resolve(cachedPublicIp);
    });
  });
}

function invalidatePublicIpCache() {
  cachedPublicIp = null;
  lastPublicIpFetch = 0;
}

/**
 * Check if candidate IP matches an office network rule.
 */
function isIpInNetwork(candidateIpStr, ruleStr) {
  if (!candidateIpStr || !ruleStr) return false;
  try {
    let clientIp = ipaddr.parse(candidateIpStr);
    if (clientIp.kind() === 'ipv6' && clientIp.isIPv4MappedAddress()) {
      clientIp = clientIp.toIPv4Address();
    }

    if (ruleStr.includes('/')) {
      const cidr = ipaddr.parseCIDR(ruleStr);
      if (clientIp.kind() === cidr[0].kind() && clientIp.match(cidr)) {
        return true;
      }
    } else {
      let targetIp = ipaddr.parse(ruleStr);
      if (targetIp.kind() === 'ipv6' && targetIp.isIPv4MappedAddress()) {
        targetIp = targetIp.toIPv4Address();
      }
      if (clientIp.kind() === targetIp.kind() && clientIp.toNormalizedString() === targetIp.toNormalizedString()) {
        return true;
      }
    }
    return false;
  } catch (e) {
    return false;
  }
}

/**
 * Authoritative Network Verification for incoming HTTP request.
 */
async function verifyRequestNetwork(req) {
  const rawRemote = getClientIp(req);
  const isLoopback = rawRemote === '127.0.0.1' || rawRemote === '::1' || rawRemote === 'localhost';
  const activeNetworks = await dbHelpers.getActiveNetworks();

  let candidateIps = [];
  let displayIp = rawRemote;

  if (isLoopback) {
    // When client runs on the local server host, evaluate the host's actual network adapter
    const publicIp = await fetchPublicIp();
    const localInterfaces = getLocalInterfaces();

    if (publicIp) candidateIps.push(publicIp);
    for (const iface of localInterfaces) {
      if (iface.ip) candidateIps.push(iface.ip);
    }

    displayIp = publicIp || (localInterfaces[0] ? localInterfaces[0].ip : '127.0.0.1');
  } else {
    candidateIps.push(rawRemote);
    displayIp = rawRemote;
  }

  let isAuthorized = false;
  let matchedNetwork = null;

  for (const net of activeNetworks) {
    // Loopback rules are strictly disallowed
    if (net.ip_or_cidr === '127.0.0.1' || net.ip_or_cidr === '::1') continue;

    for (const ip of candidateIps) {
      if (isIpInNetwork(ip, net.ip_or_cidr)) {
        isAuthorized = true;
        matchedNetwork = {
          id: net.id,
          name: net.name,
          ip_or_cidr: net.ip_or_cidr
        };
        break;
      }
    }
    if (isAuthorized) break;
  }

  return {
    clientIp: displayIp,
    isAuthorized,
    matchedNetwork,
    activeRulesCount: activeNetworks.length
  };
}

async function getSystemNetworkInfo() {
  const publicIp = await fetchPublicIp();
  const localInterfaces = getLocalInterfaces();
  const primaryIface = localInterfaces[0] || null;

  return {
    publicIp: publicIp || 'Unavailable',
    primaryLocalIp: primaryIface ? primaryIface.ip : 'Unavailable',
    primarySubnet: primaryIface ? primaryIface.subnet : 'Unavailable',
    interfaceName: primaryIface ? primaryIface.interface : 'Unavailable',
    allInterfaces: localInterfaces
  };
}

module.exports = {
  normalizeIp,
  getClientIp,
  getLocalInterfaces,
  fetchPublicIp,
  invalidatePublicIpCache,
  isIpInNetwork,
  verifyRequestNetwork,
  getSystemNetworkInfo
};
