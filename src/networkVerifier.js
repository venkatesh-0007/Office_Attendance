const os = require('node:os');
const https = require('node:https');
const ipaddr = require('ipaddr.js');
const dbHelpers = require('./db');

let cachedPublicIp = null;
let lastPublicIpFetch = 0;
const CACHE_TTL_MS = 10000; // 10 seconds cache

/**
 * Clean and normalize an IP address string.
 * Converts IPv4-mapped IPv6 (::ffff:192.168.1.1) to 192.168.1.1.
 */
function normalizeIp(ipString) {
  if (!ipString) return '127.0.0.1';
  let cleaned = ipString.trim();

  // If list from X-Forwarded-For, take the client (leftmost) IP
  if (cleaned.includes(',')) {
    cleaned = cleaned.split(',')[0].trim();
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
 * Get the machine's active non-internal IPv4 local interfaces.
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
 * Resolve the current public WAN IP of the network.
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

/**
 * Force-refresh public IP cache immediately (e.g. after admin updates network).
 */
function invalidatePublicIpCache() {
  cachedPublicIp = null;
  lastPublicIpFetch = 0;
}

/**
 * Check if a candidate IP matches an office network rule (CIDR or specific IP).
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
 * - Extracts connecting IP (x-forwarded-for, x-real-ip, or socket remoteAddress).
 * - If client is on loopback (the host machine accessing localhost), checks the host machine's
 *   actual active network: its current Public IP and its local Wi-Fi interface IP.
 * - Checks candidates against all active office networks in SQLite.
 */
async function verifyRequestNetwork(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  const rawRemote = normalizeIp(forwarded || realIp || req.socket?.remoteAddress || '127.0.0.1');

  const isLoopback = rawRemote === '127.0.0.1' || rawRemote === '::1' || rawRemote === 'localhost';
  const activeNetworks = dbHelpers.getActiveNetworks();

  let candidateIps = [];
  let displayIp = rawRemote;

  if (isLoopback) {
    // Client is running on the host machine. Test the host machine's real network!
    const publicIp = await fetchPublicIp();
    const localInterfaces = getLocalInterfaces();

    if (publicIp) candidateIps.push(publicIp);
    for (const iface of localInterfaces) {
      if (iface.ip) candidateIps.push(iface.ip);
    }

    displayIp = publicIp || (localInterfaces[0] ? localInterfaces[0].ip : '127.0.0.1');
  } else {
    // Client is a remote phone or laptop connecting over Wi-Fi / internet
    candidateIps.push(rawRemote);
    displayIp = rawRemote;
  }

  let isAuthorized = false;
  let matchedNetwork = null;

  for (const net of activeNetworks) {
    // Loopback rules are ignored for security
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

/**
 * Get current system network details for Admin Wi-Fi configuration.
 */
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
  getLocalInterfaces,
  fetchPublicIp,
  invalidatePublicIpCache,
  isIpInNetwork,
  verifyRequestNetwork,
  getSystemNetworkInfo
};
