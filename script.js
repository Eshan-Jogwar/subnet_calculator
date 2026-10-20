// IPv4 Subnet Calculator

(function () {
  'use strict';

  // DOM Elements
  const ipInput = document.getElementById('ipInput');
  const clearIpBtn = document.getElementById('clearIpBtn');
  const maskSelect = document.getElementById('maskSelect');
  const cidrSlider = document.getElementById('cidrSlider');
  const cidrBadge = document.getElementById('cidrBadge');
  const errorMessage = document.getElementById('errorMessage');
  const errorText = document.getElementById('errorText');
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const sunIcon = document.getElementById('sunIcon');
  const moonIcon = document.getElementById('moonIcon');
  const toast = document.getElementById('toast');

  // Metrics
  const mUsableHosts = document.getElementById('mUsableHosts');
  const mUsableSub = document.getElementById('mUsableSub');
  const mTotalHosts = document.getElementById('mTotalHosts');
  const mNetwork = document.getElementById('mNetwork');
  const mBroadcast = document.getElementById('mBroadcast');

  // Details
  const resIp = document.getElementById('resIp');
  const resNetwork = document.getElementById('resNetwork');
  const resMask = document.getElementById('resMask');
  const resWildcard = document.getElementById('resWildcard');
  const resCidr = document.getElementById('resCidr');
  const resUsableRange = document.getElementById('resUsableRange');
  const resFirstHost = document.getElementById('resFirstHost');
  const resLastHost = document.getElementById('resLastHost');
  const resBroadcast = document.getElementById('resBroadcast');
  const resScope = document.getElementById('resScope');
  const resClass = document.getElementById('resClass');
  const resHex = document.getElementById('resHex');
  const resPtr = document.getElementById('resPtr');

  // Binary outputs
  const binIp = document.getElementById('binIp');
  const binMask = document.getElementById('binMask');
  const binNet = document.getElementById('binNet');
  const binBcast = document.getElementById('binBcast');

  // Subdivider
  const subdivideSelect = document.getElementById('subdivideSelect');
  const subdivideTableContainer = document.getElementById('subdivideTableContainer');

  // Initialize Mask Dropdown
  function populateMaskOptions() {
    maskSelect.innerHTML = '';
    for (let cidr = 32; cidr >= 0; cidr--) {
      const maskInt = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
      const maskStr = intToIp(maskInt);
      const totalHosts = Math.pow(2, 32 - cidr);
      const option = document.createElement('option');
      option.value = cidr;
      option.textContent = `/${cidr} - ${maskStr} (${formatNumber(totalHosts)} addresses)`;
      maskSelect.appendChild(option);
    }
  }

  // Bitwise IP helpers
  function ipToInt(ip) {
    const octets = ip.split('.').map(Number);
    return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  }

  function intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }

  function intToBinaryString(int) {
    return (int >>> 0).toString(2).padStart(32, '0');
  }

  function formatNumber(num) {
    return Number(num).toLocaleString('en-US');
  }

  // Validate IPv4 format
  function validateIp(ip) {
    if (!ip) return false;
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return false;

    for (let i = 0; i < 4; i++) {
      const part = parts[i];
      if (!/^\d+$/.test(part)) return false;
      const num = parseInt(part, 10);
      if (num < 0 || num > 255) return false;
      if (part.length > 1 && part.startsWith('0')) return false; // Prevent octal notation e.g. 010
    }
    return true;
  }

  // Classify IP Class
  function getIpClass(firstOctet) {
    if (firstOctet >= 0 && firstOctet <= 127) return 'Class A';
    if (firstOctet >= 128 && firstOctet <= 191) return 'Class B';
    if (firstOctet >= 192 && firstOctet <= 223) return 'Class C';
    if (firstOctet >= 224 && firstOctet <= 239) return 'Class D (Multicast)';
    return 'Class E (Experimental)';
  }

  // Classify IP Scope / Type
  function getIpScope(ipInt) {
    const o1 = (ipInt >>> 24) & 255;
    const o2 = (ipInt >>> 16) & 255;

    // 10.0.0.0/8
    if (o1 === 10) {
      return { label: 'Private (RFC 1918)', class: 'tag-private' };
    }
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) {
      return { label: 'Private (RFC 1918)', class: 'tag-private' };
    }
    // 192.168.0.0/16
    if (o1 === 192 && o2 === 168) {
      return { label: 'Private (RFC 1918)', class: 'tag-private' };
    }
    // 127.0.0.0/8
    if (o1 === 127) {
      return { label: 'Loopback (RFC 1122)', class: 'tag-loopback' };
    }
    // 169.254.0.0/16 (APIPA)
    if (o1 === 169 && o2 === 254) {
      return { label: 'Link-Local / APIPA (RFC 3927)', class: 'tag-special' };
    }
    // 100.64.0.0/10 (CGNAT RFC 6598: 100.64.0.0 - 100.127.255.255)
    if (o1 === 100 && o2 >= 64 && o2 <= 127) {
      return { label: 'Carrier-Grade NAT (RFC 6598)', class: 'tag-special' };
    }
    // 224.0.0.0/4 Multicast
    if (o1 >= 224 && o1 <= 239) {
      return { label: 'Multicast (RFC 5771)', class: 'tag-special' };
    }
    // 240.0.0.0/4 Reserved
    if (o1 >= 240) {
      return { label: 'Reserved / Experimental', class: 'tag-special' };
    }
    // 0.0.0.0/8
    if (o1 === 0) {
      return { label: 'This Network (RFC 1122)', class: 'tag-special' };
    }

    return { label: 'Public Internet', class: 'tag-public' };
  }

  // Format binary with network and host styling
  function renderBinaryWithColors(binStr, cidr) {
    let result = '';
    for (let i = 0; i < 32; i++) {
      if (i > 0 && i % 8 === 0) {
        result += '<span class="octet-sep">.</span>';
      }
      const bit = binStr[i];
      const isNet = i < cidr;
      result += `<span class="${isNet ? 'net-bit' : 'host-bit'}">${bit}</span>`;
    }
    return result;
  }

  // Main calculation function
  function calculate() {
    let rawIp = ipInput.value.trim();

    // Check if user entered CIDR notation in the IP box (e.g., 10.0.0.1/24)
    if (rawIp.includes('/')) {
      const slashParts = rawIp.split('/');
      const parsedIp = slashParts[0].trim();
      const parsedCidr = parseInt(slashParts[1], 10);

      if (!isNaN(parsedCidr) && parsedCidr >= 0 && parsedCidr <= 32) {
        cidrSlider.value = parsedCidr;
        maskSelect.value = parsedCidr;
        cidrBadge.textContent = `/${parsedCidr}`;
      }
      rawIp = parsedIp;
      ipInput.value = rawIp;
    }

    if (!validateIp(rawIp)) {
      showError('Please enter a valid IPv4 address (e.g. 192.168.1.1)');
      return;
    }

    hideError();

    const cidr = parseInt(cidrSlider.value, 10);
    const ipInt = ipToInt(rawIp);
    const maskInt = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
    const wildcardInt = (~maskInt) >>> 0;
    const networkInt = (ipInt & maskInt) >>> 0;
    const broadcastInt = (networkInt | wildcardInt) >>> 0;

    const totalHosts = Math.pow(2, 32 - cidr);
    let usableHosts = 0;
    let firstUsableInt = 0;
    let lastUsableInt = 0;
    let usableRangeStr = '';

    if (cidr === 32) {
      usableHosts = 1;
      firstUsableInt = networkInt;
      lastUsableInt = networkInt;
      usableRangeStr = `${intToIp(firstUsableInt)} (Single Host Route)`;
    } else if (cidr === 31) {
      usableHosts = 2; // RFC 3021 Point-to-Point
      firstUsableInt = networkInt;
      lastUsableInt = broadcastInt;
      usableRangeStr = `${intToIp(firstUsableInt)} - ${intToIp(lastUsableInt)} (RFC 3021 P2P)`;
    } else if (cidr === 0) {
      usableHosts = totalHosts - 2;
      firstUsableInt = (networkInt + 1) >>> 0;
      lastUsableInt = (broadcastInt - 1) >>> 0;
      usableRangeStr = `${intToIp(firstUsableInt)} - ${intToIp(lastUsableInt)}`;
    } else {
      usableHosts = Math.max(0, totalHosts - 2);
      firstUsableInt = (networkInt + 1) >>> 0;
      lastUsableInt = (broadcastInt - 1) >>> 0;
      usableRangeStr = `${intToIp(firstUsableInt)} - ${intToIp(lastUsableInt)}`;
    }

    // Update Summary Metrics
    mUsableHosts.textContent = formatNumber(usableHosts);
    if (cidr === 31) {
      mUsableSub.textContent = 'Point-to-Point Links (RFC 3021)';
    } else if (cidr === 32) {
      mUsableSub.textContent = 'Single host route';
    } else {
      mUsableSub.textContent = 'Addresses assignable to devices';
    }

    mTotalHosts.textContent = formatNumber(totalHosts);
    mNetwork.textContent = intToIp(networkInt);
    mBroadcast.textContent = intToIp(broadcastInt);

    // Update Detailed Table
    resIp.textContent = rawIp;
    resNetwork.textContent = intToIp(networkInt);
    resMask.textContent = intToIp(maskInt);
    resWildcard.textContent = intToIp(wildcardInt);
    resCidr.textContent = `${intToIp(networkInt)}/${cidr}`;
    resUsableRange.textContent = usableRangeStr;
    resFirstHost.textContent = intToIp(firstUsableInt);
    resLastHost.textContent = intToIp(lastUsableInt);
    resBroadcast.textContent = intToIp(broadcastInt);

    // Scope & Class
    const scope = getIpScope(ipInt);
    resScope.innerHTML = `<span class="tag ${scope.class}">${scope.label}</span>`;

    const firstOctet = (ipInt >>> 24) & 255;
    const ipClass = getIpClass(firstOctet);
    resClass.innerHTML = `<span class="tag tag-class">${ipClass}</span>`;

    // Hex & Reverse DNS (PTR)
    resHex.textContent = '0x' + ipInt.toString(16).toUpperCase().padStart(8, '0');
    const octets = rawIp.split('.');
    resPtr.textContent = `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;

    // Binary breakdown
    binIp.innerHTML = renderBinaryWithColors(intToBinaryString(ipInt), cidr);
    binMask.innerHTML = renderBinaryWithColors(intToBinaryString(maskInt), cidr);
    binNet.innerHTML = renderBinaryWithColors(intToBinaryString(networkInt), cidr);
    binBcast.innerHTML = renderBinaryWithColors(intToBinaryString(broadcastInt), cidr);

    // Update Subnet Subdivider options
    updateSubdividerOptions(cidr, networkInt);
  }

  // Subnet Subdivider Logic
  function updateSubdividerOptions(currentCidr, networkInt) {
    subdivideSelect.innerHTML = '';

    if (currentCidr >= 30) {
      subdivideSelect.innerHTML = '<option disabled>Already at minimum subnet size</option>';
      subdivideTableContainer.innerHTML = '<p class="helper-text">Cannot further divide a /30, /31, or /32 network into smaller standard subnets.</p>';
      return;
    }

    for (let newCidr = currentCidr + 1; newCidr <= Math.min(32, currentCidr + 8); newCidr++) {
      const numSubnets = Math.pow(2, newCidr - currentCidr);
      const hostsPerSubnet = Math.pow(2, 32 - newCidr);
      const opt = document.createElement('option');
      opt.value = newCidr;
      opt.textContent = `/${newCidr} (${formatNumber(numSubnets)} subnets of ${formatNumber(hostsPerSubnet)} IPs)`;
      subdivideSelect.appendChild(opt);
    }

    // Default select first available option
    renderSubdivideTable(parseInt(subdivideSelect.value, 10), currentCidr, networkInt);
  }

  function renderSubdivideTable(newCidr, currentCidr, parentNetworkInt) {
    if (!newCidr || isNaN(newCidr)) return;

    const subnetsCount = Math.pow(2, newCidr - currentCidr);
    const subnetSize = Math.pow(2, 32 - newCidr);
    const maxRows = 64; // Limit render to avoid UI lockup on huge divisions
    const displayCount = Math.min(subnetsCount, maxRows);

    let html = `
      <table class="subdivide-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Subnet CIDR</th>
            <th>Network Address</th>
            <th>Usable Host Range</th>
            <th>Broadcast</th>
            <th>Usable Hosts</th>
          </tr>
        </thead>
        <tbody>
    `;

    for (let i = 0; i < displayCount; i++) {
      const netInt = (parentNetworkInt + (i * subnetSize)) >>> 0;
      const bcastInt = (netInt + subnetSize - 1) >>> 0;
      let firstHost, lastHost, usableHosts;

      if (newCidr === 32) {
        firstHost = netInt;
        lastHost = netInt;
        usableHosts = 1;
      } else if (newCidr === 31) {
        firstHost = netInt;
        lastHost = bcastInt;
        usableHosts = 2;
      } else {
        firstHost = (netInt + 1) >>> 0;
        lastHost = (bcastInt - 1) >>> 0;
        usableHosts = Math.max(0, subnetSize - 2);
      }

      html += `
        <tr>
          <td>${i + 1}</td>
          <td><strong style="color: var(--primary)">${intToIp(netInt)}/${newCidr}</strong></td>
          <td>${intToIp(netInt)}</td>
          <td>${intToIp(firstHost)} - ${intToIp(lastHost)}</td>
          <td>${intToIp(bcastInt)}</td>
          <td>${formatNumber(usableHosts)}</td>
        </tr>
      `;
    }

    html += `</tbody></table>`;

    if (subnetsCount > maxRows) {
      html += `<p class="helper-text mt-3">Showing first ${maxRows} of ${formatNumber(subnetsCount)} total subnets.</p>`;
    }

    subdivideTableContainer.innerHTML = html;
  }

  // Error Banner helpers
  function showError(msg) {
    errorText.textContent = msg;
    errorMessage.classList.remove('hidden');
  }

  function hideError() {
    errorMessage.classList.add('hidden');
  }

  // Toast Notification
  let toastTimer = null;
  function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, 2200);
  }

  // Copy to clipboard helper
  function copyTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied "${text}" to clipboard`);
      }).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const tempInput = document.createElement('textarea');
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    try {
      document.execCommand('copy');
      showToast(`Copied "${text}" to clipboard`);
    } catch (e) {
      showToast('Failed to copy');
    }
    document.body.removeChild(tempInput);
  }

  // Event Listeners
  function setupEventListeners() {
    // IP input changed
    ipInput.addEventListener('input', calculate);

    // Clear IP button
    clearIpBtn.addEventListener('click', () => {
      ipInput.value = '';
      ipInput.focus();
      showError('Please enter an IPv4 address');
    });

    // Mask select changed
    maskSelect.addEventListener('change', () => {
      const cidr = maskSelect.value;
      cidrSlider.value = cidr;
      cidrBadge.textContent = `/${cidr}`;
      calculate();
    });

    // Slider changed
    cidrSlider.addEventListener('input', () => {
      const cidr = cidrSlider.value;
      maskSelect.value = cidr;
      cidrBadge.textContent = `/${cidr}`;
      calculate();
    });

    // Preset buttons
    document.querySelectorAll('.preset-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const ip = chip.getAttribute('data-ip');
        const cidr = chip.getAttribute('data-cidr');
        ipInput.value = ip;
        cidrSlider.value = cidr;
        maskSelect.value = cidr;
        cidrBadge.textContent = `/${cidr}`;
        calculate();
      });
    });

    // Copy buttons
    document.addEventListener('click', (e) => {
      if (e.target && e.target.classList.contains('copy-btn')) {
        const targetId = e.target.getAttribute('data-target');
        const targetEl = document.getElementById(targetId);
        if (targetEl) {
          copyTextToClipboard(targetEl.textContent.trim());
        }
      }
    });

    // Subdivider dropdown change
    subdivideSelect.addEventListener('change', () => {
      const rawIp = ipInput.value.trim().split('/')[0];
      if (validateIp(rawIp)) {
        const cidr = parseInt(cidrSlider.value, 10);
        const ipInt = ipToInt(rawIp);
        const maskInt = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
        const netInt = (ipInt & maskInt) >>> 0;
        renderSubdivideTable(parseInt(subdivideSelect.value, 10), cidr, netInt);
      }
    });

    // Theme toggle
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      setTheme(newTheme);
    });
  }

  // Theme Management
  function setTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
      localStorage.setItem('subnet_theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
      localStorage.setItem('subnet_theme', 'dark');
    }
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('subnet_theme');
    if (savedTheme) {
      setTheme(savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      setTheme('light');
    } else {
      setTheme('dark');
    }
  }

  // Initial startup
  function init() {
    populateMaskOptions();
    initTheme();
    setupEventListeners();

    // Set initial values
    cidrSlider.value = 24;
    maskSelect.value = 24;
    cidrBadge.textContent = '/24';

    calculate();
  }

  init();
})();
