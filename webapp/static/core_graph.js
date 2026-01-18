/* Core Topology Graph Logic (extracted from core_details.html)
 * Features:
 * - Force layout (grid mode removed)
 * - Optional clustering by type
 * - Mini-map viewport tracking
 * - Export (SVG / PNG)
 * - Delayed tooltip (500ms)
 * - Rectangle nodes sized by services count
 * - Persisted positions and pinning
 * - Manual zoom reset (Fit removed)
 * - Label wrapping, multi-line service count indicator
 */
(function(window, document, d3){
  function initCoreGraph(options){
    const {
      containerSelector = '#topologyGraph',
      nodes = [],
      linksRaw = [],
      xmlPath = '_default'
    } = options || {};
    const container = document.querySelector(containerSelector);
    if(!container || !nodes.length){ return; }

    // Build links index mapping id/name -> index
    const idIndex = new Map();
    nodes.forEach((n,i)=>{ idIndex.set(String(n.id), i); idIndex.set(String(n.name), i); });
    const links = [];
    linksRaw.forEach(l => {
      const s = idIndex.get(String(l.node1)) ?? idIndex.get(String(l.node1_name));
      const t = idIndex.get(String(l.node2)) ?? idIndex.get(String(l.node2_name));
      if(s===undefined||t===undefined||s===t) return; links.push({ source:s, target:t });
    });

    // Restore positions
    // Versioned key to avoid inheriting corrupted/legacy saved layouts.
    const storageKey = 'coretg_graph_positions_v2_' + xmlPath;
    let restoredPositions = {}; try { restoredPositions = JSON.parse(localStorage.getItem(storageKey)||'{}'); } catch(e){}
    nodes.forEach(n => {
      const saved = restoredPositions[n.id];
      if(!saved) return;
      const sx = Number(saved.x);
      const sy = Number(saved.y);
      if(Number.isFinite(sx)) n.x = sx;
      if(Number.isFinite(sy)) n.y = sy;
      // Only restore pins that were intentionally created via dragging.
      // This avoids older persisted "pinned" states from accidental click-release.
      if(saved.pinned_by_drag === true){
        if(Number.isFinite(sx)) n.fx = sx;
        if(Number.isFinite(sy)) n.fy = sy;
        n.__pinned_by_drag = true;
      }
    });

    const width = container.clientWidth; const height = container.clientHeight;
    const __initialContainerSize = { w: width, h: height };
    let __autoResetOnFirstShowDone = false;
    const svg = d3.select(container).append('svg')
      .attr('width', width)
      .attr('height', height)
      .style('cursor','grab')
      .on('mousedown', ()=> svg.style('cursor','grabbing'))
      .on('mouseup mouseleave', ()=> svg.style('cursor','grab'));

    const g = svg.append('g');
    // Prevent zoom/pan from hijacking node drags.
    // Allow wheel zoom anywhere, but disable mouse-drag panning when the gesture starts on a node.
    const zoomBehavior = d3.zoom()
      .scaleExtent([0.15,6])
      .filter((ev)=>{
        try {
          if(!ev) return true;
          if(ev.type === 'wheel') return true;
          const t = (ev && ev.sourceEvent && ev.sourceEvent.target) ? ev.sourceEvent.target : ev.target;
          if(t && typeof t.closest === 'function' && t.closest('g.node')) return false;
          return true;
        } catch(e){
          return true;
        }
      })
      .on('zoom', ev=> { g.attr('transform', ev.transform); updateMiniMapViewport(ev.transform); });
    svg.call(zoomBehavior);

    const vulnerabilityColor = '#ff0000';
    const sequenceColor = '#ff0000';
    const hitlColor = '#2e7d32';
    const hitlMarkers = ['rj45','rj-45','hitl','tap','bridge','ethernet','physical'];
    const typeColor = d3.scaleOrdinal()
      // Note: docker and vulnerability intentionally share fill color; docker is distinguished via dashed outline.
      .domain(['router','switch','hub','wlan','host','pc','server','docker','vulnerability','node','hitl'])
      .range(['#d9534f','#f0ad4e','#5bc0de','#5cb85c','#0275d8','#6610f2','#6f42c1', vulnerabilityColor, vulnerabilityColor,'#607d8b', hitlColor]);

    function nodeTypeNormalized(node){
      try { return String(node?.type || '').trim().toLowerCase(); } catch(e){ return ''; }
    }

    function nodeIsDocker(node){
      const t = nodeTypeNormalized(node);
      if(!t) return false;
      if(t === 'docker' || t.includes('docker')) return true;
      try {
        const comp = String(node?.compose || '').trim();
        const compName = String(node?.compose_name || '').trim();
        return !!(comp || compName);
      } catch(e){
        return false;
      }
    }

    function nodeHasVulnerabilities(node){
      if(!node) return false;
      const vulnList = Array.isArray(node.vulnerabilities) ? node.vulnerabilities
        : (node.metadata && Array.isArray(node.metadata.vulnerabilities) ? node.metadata.vulnerabilities : []);
      return (Array.isArray(vulnList) && vulnList.length > 0) || !!node.hasVuln || node.is_vulnerability === true || node.is_vuln === true;
    }

    function nodeIsHitl(node){
      if(!node) return false;
      if(node.is_hitl === true || node.is_hitl === 'true' || node.is_hitl === 'True'){ return true; }
      const typeVal = (node.type||'').toLowerCase();
      if(typeVal && hitlMarkers.some(marker => typeVal.includes(marker))){ return true; }
      const nameVal = (node.name||'').toLowerCase();
      if(nameVal && hitlMarkers.some(marker => nameVal.includes(marker))){ return true; }
      return false;
    }

    // Pin HITL nodes away from the rest of the topology and label them clearly.
    // This mirrors the intent of the details page where HITL nodes are distinct,
    // and prevents the HITL gateway (e.g., ens19) from blending into LAN/switch clusters.
    function placeHitlNodes(viewW, viewH){
      try {
        const hitlNodes = nodes.filter(n => nodeIsHitl(n));
        if(!hitlNodes.length) return;
        hitlNodes.sort((a,b)=> String(a.id ?? a.name ?? '').localeCompare(String(b.id ?? b.name ?? '')));
        // Keep HITL as far away from the main topology as possible while staying in-bounds.
        const marginRight = 60;
        const startY = 90;
        const gapY = 140;
        const x = Math.max(160, (viewW || width) - marginRight);
        hitlNodes.forEach((n, i)=>{
          const y = Math.max(90, Math.min((viewH || height) - 90, startY + i * gapY));
          n.fx = x;
          n.fy = y;
          n.x = x;
          n.y = y;
        });
      } catch(e){}
    }

    // Ensure a CSS animation exists for the HITL callout label.
    (function ensureHereLabelAnimation(){
      try {
        if(document.getElementById('hereLabelAnimStyle')) return;
        const style = document.createElement('style');
        style.id = 'hereLabelAnimStyle';
        style.textContent = `
@keyframes hereLabelFlash { 0% { opacity: 1; } 50% { opacity: 0.15; } 100% { opacity: 1; } }
.here-label-flash { animation: hereLabelFlash 0.5s linear infinite; }
`;
        document.head.appendChild(style);
      } catch(e){}
    })();

    function nodeCategory(node){
      if(nodeIsHitl(node)){ return 'hitl'; }
      if(nodeIsDocker(node)) return 'docker';
      const t = nodeTypeNormalized(node);
      return t || 'node';
    }

    function nodeFillColor(node){
      if(nodeIsHitl(node)){ return hitlColor; }
      const cat = nodeCategory(node);
      if(cat === 'vulnerability' || cat === 'docker') return vulnerabilityColor;
      const typeVal = nodeTypeNormalized(node);
      if(nodeHasVulnerabilities(node) && (typeVal === 'host' || typeVal === 'pc' || typeVal === 'server')){
        return vulnerabilityColor;
      }
      return typeColor(nodeCategory(node));
    }

    function primaryIpv4(node){
      if(!node) return '';
      const list = Array.isArray(node.ipv4s) ? node.ipv4s : [];
      const first = list.find(v => v && String(v).trim());
      if(first) return String(first).trim();
      const ifaces = Array.isArray(node.interfaces) ? node.interfaces : [];
      for(const iface of ifaces){
        if(!iface || typeof iface !== 'object') continue;
        const ip = (iface.ipv4 || iface.ip4 || '').toString().trim();
        if(ip) return ip.split('/', 1)[0];
      }
      return '';
    }

    function labelFill(node){
      if(nodeIsHitl(node)) return '#000';
      return ((node?.type||'').toLowerCase()==='switch') ? '#000' : '#fff';
    }

    function nodeSequenceIndex(node){
      try {
        const raw = (node && (node.sequence_index ?? node.sequenceIndex)) ? Number(node.sequence_index ?? node.sequenceIndex) : null;
        return (raw && Number.isFinite(raw)) ? raw : null;
      } catch(e){
        return null;
      }
    }

    function toRoman(num){
      const n = Number(num);
      if(!Number.isFinite(n) || n <= 0 || n >= 4000) return '';
      const parts = [
        [1000,'M'],[900,'CM'],[500,'D'],[400,'CD'],
        [100,'C'],[90,'XC'],[50,'L'],[40,'XL'],
        [10,'X'],[9,'IX'],[5,'V'],[4,'IV'],[1,'I'],
      ];
      let x = Math.floor(n);
      let out = '';
      for(const [v,s] of parts){
        while(x >= v){ out += s; x -= v; }
      }
      return out;
    }

    function displayName(node){
      const raw = String(node?.name || '');
      if(!raw) return '';
      if(!nodeIsHitl(node)) return raw;
      // Avoid showing IP/CIDR-like info on the HITL node label.
      // Example: "ens19 (10.0.0.0/24)" -> "ens19".
      return raw.replace(/\s*\(([^)]*[\d.:]+[^)]*)\)\s*$/,'').trim();
    }

    function displayNameWithSequence(node){
      const base = displayName(node);
      if(!base) return '';
      if(nodeIsHitl(node)) return base;
      const seq = nodeSequenceIndex(node);
      if(!seq) return base;
      const roman = toRoman(seq);
      return roman ? (roman + ' ' + base) : base;
    }

    function boxW(node){
      const svc = (node?.services||[]).length;
      const base = 110 + Math.min(120, svc * 10);
      const nameLen = String(displayNameWithSequence(node) || '').length;
      const ipLen = nodeIsHitl(node) ? 0 : String(primaryIpv4(node) || '').length;
      // Heuristic text fit: ~6.4px per char at 10px font, plus padding.
      const textNeed = (Math.max(nameLen, ipLen) * 6.4) + 26;
      // Allow wider boxes so the IP line doesn't spill outside the node.
      // Keep an upper bound to avoid giant boxes from unusually long names.
      return Math.max(base, Math.min(560, textNeed));
    }

    function boxH(node){
      const svc = (node?.services||[]).length;
      const base = 44 + Math.min(34, svc * 1.35);
      if(nodeIsHitl(node)) return base;
      return base + (primaryIpv4(node) ? 14 : 0);
    }

    const linkCounts = new Array(nodes.length).fill(0); links.forEach(l => { linkCounts[l.source]++; linkCounts[l.target]++; });

    // Network-diagram-like tiering (keeps it readable vs. pure force soup)
    function nodeTier(node){
      const t = nodeTypeNormalized(node);
      if(t === 'router') return 0;
      if(t === 'switch' || t === 'hub' || t === 'wlan') return 1;
      if(t === 'host' || t === 'pc' || t === 'server' || nodeIsDocker(node) || t === 'vulnerability' || t === 'node') return 2;
      if(nodeIsHitl(node)) return 2;
      return 2;
    }

    const tiers = nodes.map(n => nodeTier(n));
    const tierBuckets = new Map();
    tiers.forEach((tier, idx)=>{
      const arr = tierBuckets.get(tier) || [];
      arr.push(idx);
      tierBuckets.set(tier, arr);
    });

    // Primary subnet per node (used to horizontally separate subnet groups)
    function primarySubnet(node){
      const list = Array.isArray(node?.subnets) ? node.subnets : [];
      const first = list.find(v => v && String(v).trim());
      return first ? String(first).trim() : '';
    }

    const subnetKeys = Array.from(new Set(nodes.map(n => primarySubnet(n)).filter(Boolean))).sort();
    const subnetMembers = new Map();
    nodes.forEach((n, idx)=>{
      if(nodeTier(n) === 0) return; // routers excluded from subnet boxes/lanes
      const key = primarySubnet(n);
      if(!key) return;
      const arr = subnetMembers.get(key) || [];
      arr.push(idx);
      subnetMembers.set(key, arr);
    });

    // Use link structure to arrange routers → switches → hosts horizontally.
    // This produces a more network-diagram-like layout than evenly spreading by type.
    const neighbors = new Array(nodes.length).fill(0).map(()=> new Set());
    links.forEach(l => {
      const s = l.source; const t = l.target;
      if(typeof s !== 'number' || typeof t !== 'number') return;
      if(s === t) return;
      neighbors[s].add(t);
      neighbors[t].add(s);
    });

    const routerIdxs = (tierBuckets.get(0) || []).slice();
    const switchIdxs = (tierBuckets.get(1) || []).slice();
    const hostIdxs = (tierBuckets.get(2) || []).slice();

    const nodeKey = (idx) => {
      const n = nodes[idx] || {};
      return String(n.id ?? n.name ?? idx);
    };

    const pickPrimary = (candidates) => {
      if(!candidates || !candidates.length) return null;
      const sorted = candidates.slice().sort((a,b)=> nodeKey(a).localeCompare(nodeKey(b)));
      return sorted[0];
    };

    const switchToRouter = new Map();
    switchIdxs.forEach(sw => {
      const rNbrs = Array.from(neighbors[sw] || []).filter(nbr => tiers[nbr] === 0);
      const primary = pickPrimary(rNbrs);
      if(primary != null) switchToRouter.set(sw, primary);
    });

    const routerToSwitches = new Map();
    routerIdxs.forEach(r => routerToSwitches.set(r, []));
    const unassignedSwitches = [];
    switchIdxs.forEach(sw => {
      const r = switchToRouter.get(sw);
      if(r != null && routerToSwitches.has(r)) routerToSwitches.get(r).push(sw);
      else unassignedSwitches.push(sw);
    });

    const hostToSwitch = new Map();
    hostIdxs.forEach(h => {
      const sNbrs = Array.from(neighbors[h] || []).filter(nbr => tiers[nbr] === 1);
      const primary = pickPrimary(sNbrs);
      if(primary != null) hostToSwitch.set(h, primary);
    });

    const switchToHosts = new Map();
    switchIdxs.forEach(sw => switchToHosts.set(sw, []));
    const unassignedHosts = [];
    hostIdxs.forEach(h => {
      const sw = hostToSwitch.get(h);
      if(sw != null && switchToHosts.has(sw)) switchToHosts.get(sw).push(h);
      else unassignedHosts.push(h);
    });

    function tierY(tier){
      // Larger vertical separation so routers sit clearly above distribution/access layers.
      if(tier === 0) return height * 0.10;
      if(tier === 1) return height * 0.56;
      return height * 0.93;
    }

    function tierXFallback(idx){
      const tier = tiers[idx] ?? 2;
      const bucket = tierBuckets.get(tier) || [idx];
      const pos = bucket.indexOf(idx);
      const n = Math.max(1, bucket.length);
      const pad = 40;
      if(n === 1) return width / 2;
      const frac = pos / (n - 1);
      return pad + frac * Math.max(1, (width - pad * 2));
    }

    const preferredX = new Array(nodes.length).fill(0).map((_,i)=> tierXFallback(i));
    if(routerIdxs.length){
      const pad = 90;
      const slotW = Math.max(320, (width - pad * 2) / Math.max(1, routerIdxs.length));
      const routerOrder = routerIdxs.slice().sort((a,b)=> nodeKey(a).localeCompare(nodeKey(b)));

      routerOrder.forEach((r, i) => {
        const cx = pad + slotW * (i + 0.5);
        preferredX[r] = cx;

        const sws = (routerToSwitches.get(r) || []).slice().sort((a,b)=> nodeKey(a).localeCompare(nodeKey(b)));
        if(sws.length){
          // Spread switches wider under each router (more separation from the router node).
          const inner = Math.max(420, slotW * 1.35);
          const left = cx - inner / 2;
          const right = cx + inner / 2;
          const denom = Math.max(1, (sws.length - 1));
          sws.forEach((sw, j) => {
            const x = sws.length === 1 ? cx : (left + (j / denom) * (right - left));
            preferredX[sw] = x;
            const hs = (switchToHosts.get(sw) || []).slice().sort((a,b)=> nodeKey(a).localeCompare(nodeKey(b)));
            if(hs.length){
              // Spread hosts wider under each switch.
              const span = Math.min(520, Math.max(260, inner * 0.78));
              const hLeft = x - span / 2;
              const hRight = x + span / 2;
              const hDen = Math.max(1, (hs.length - 1));
              hs.forEach((h, k) => {
                preferredX[h] = (hs.length === 1) ? x : (hLeft + (k / hDen) * (hRight - hLeft));
              });
            }
          });
        }
      });

      // Place switches/hosts that couldn't be attached to the hierarchy using fallback spread.
      unassignedSwitches.forEach(sw => { preferredX[sw] = tierXFallback(sw); });
      unassignedHosts.forEach(h => { preferredX[h] = tierXFallback(h); });
    }

    // Compute subnet lane centers based on the *actual* preferred footprint of each subnet.
    const subnetCenterX = new Map();
    if(subnetKeys.length){
      const gap = 240;
      const pad = 160;
      const widths = subnetKeys.map(key => {
        const idxs = subnetMembers.get(key) || [];
        if(!idxs.length) return 420;
        let minX = Infinity, maxX = -Infinity;
        idxs.forEach(i => {
          const x = preferredX[i];
          const w = boxW(nodes[i]);
          minX = Math.min(minX, x - w/2);
          maxX = Math.max(maxX, x + w/2);
        });
        if(!Number.isFinite(minX) || !Number.isFinite(maxX)) return 420;
        return Math.max(420, Math.min(2200, (maxX - minX) + 320));
      });

      let cursor = pad;
      subnetKeys.forEach((key, i)=>{
        const w = widths[i];
        const center = cursor + w / 2;
        subnetCenterX.set(key, center);
        cursor = center + w / 2 + gap;
      });

      const total = cursor - gap + pad;
      if(Number.isFinite(total) && total < width){
        const shift = (width - total) / 2;
        subnetKeys.forEach(key => subnetCenterX.set(key, (subnetCenterX.get(key) || 0) + shift));
      }
    }

    // Subnet-aware horizontal bias: keep hierarchy but push each subnet group into its own lane.
    if(subnetCenterX.size){
      nodes.forEach((n, i)=>{
        const tier = tiers[i] ?? 2;
        if(tier === 0) return; // never bias routers into subnet lanes
        const sn = primarySubnet(n);
        const cx = sn ? subnetCenterX.get(sn) : null;
        if(cx == null) return;
        const w = (tier === 1 ? 0.80 : 0.90);
        preferredX[i] = preferredX[i] * (1 - w) + cx * w;
      });
    }

    function tierX(idx){
      return preferredX[idx] ?? tierXFallback(idx);
    }

    // Seed initial positions into tiers to reduce "explosion" on first tick.
    nodes.forEach((n, i)=>{
      if(n.x == null || n.y == null){
        n.x = tierX(i);
        n.y = tierY(tiers[i] ?? 2);
      }
    });

    // Ensure HITL node(s) start in a stable, separated location.
    placeHitlNodes(width, height);

    let clusterMode = 'off';

    function linkTierDistance(l){
      const sObj = (l && typeof l.source === 'object') ? l.source : nodes[l?.source];
      const tObj = (l && typeof l.target === 'object') ? l.target : nodes[l?.target];
      const a = nodeTier(sObj);
      const b = nodeTier(tObj);
      // router↔switch longer; switch↔host medium; router↔router also long.
      if((a === 0 && b === 1) || (a === 1 && b === 0)) return 360;
      if((a === 1 && b === 2) || (a === 2 && b === 1)) return 230;
      if(a === 0 && b === 0) return 300;
      return 210;
    }

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d,i)=> i).distance(linkTierDistance).strength(0.28))
      .force('charge', d3.forceManyBody().strength(-520))
      .force('center', d3.forceCenter(width/2, height/2))
      .force('tierY', d3.forceY((d)=> tierY(nodeTier(d))).strength(0.18))
      .force('tierX', d3.forceX((d)=> tierX(d.index ?? 0)).strength(0.30))
      .force('subnetX', d3.forceX(d => {
        if(nodeTier(d) === 0) return width / 2;
        const sn = primarySubnet(d);
        const cx = sn ? subnetCenterX.get(sn) : null;
        return (cx != null) ? cx : (d.x ?? width/2);
      }).strength(0.22))
      .force('collision', d3.forceCollide().radius(d => {
        const w = boxW(d);
        const h = boxH(d);
        return Math.max(w,h)/2 + 32;
      }));

    // Subnet bounding boxes (behind everything)
    const subnetLayer = g.append('g').attr('class', 'subnet-layer');

    function nodeSubnets(node){
      // Use the primary subnet only to keep boxes disjoint and avoid overlaps.
      const one = primarySubnet(node);
      return one ? [one] : [];
    }

    function buildSubnetGroups(){
      const groups = new Map();
      nodes.forEach((n, idx)=>{
        // Routers often have interfaces in multiple subnets; subnet boxes should
        // represent L2/LAN groupings, so exclude routers from these boxes.
        if(nodeTier(n) === 0) return;
        const subs = nodeSubnets(n);
        subs.forEach(cidr => {
          const arr = groups.get(cidr) || [];
          arr.push(idx);
          groups.set(cidr, arr);
        });
      });
      // Keep groups with at least 2 nodes (prevents lots of noisy single-node boxes).
      const out = Array.from(groups.entries())
        .filter(([_, idxs]) => idxs.length >= 2)
        .map(([cidr, idxs]) => ({ cidr, idxs: idxs.slice() }))
        .sort((a,b)=> a.cidr.localeCompare(b.cidr));
      return out;
    }

    let subnetGroups = buildSubnetGroups();
    // While a node is being dragged, subnet packing and box resizing can cause
    // large, surprising shifts (especially when a dragged node expands a subnet
    // bounding box). Track active drags so we can temporarily freeze these.
    let __activeDragCount = 0;

    function _freezeOtherNodes(activeNode){
      try {
        nodes.forEach(n => {
          if(!n || n === activeNode) return;
          if(n.__frozen_by_drag === true) return;
          n.__frozen_by_drag = true;
          n.__frozen_prev_fx = (n.fx != null) ? n.fx : null;
          n.__frozen_prev_fy = (n.fy != null) ? n.fy : null;
          if(Number.isFinite(n.x)) n.fx = n.x;
          if(Number.isFinite(n.y)) n.fy = n.y;
        });
      } catch(e){}
    }

    function _unfreezeOtherNodes(){
      try {
        nodes.forEach(n => {
          if(!n || n.__frozen_by_drag !== true) return;
          const prevFx = n.__frozen_prev_fx;
          const prevFy = n.__frozen_prev_fy;
          n.fx = (prevFx != null && Number.isFinite(prevFx)) ? prevFx : null;
          n.fy = (prevFy != null && Number.isFinite(prevFy)) ? prevFy : null;
          delete n.__frozen_by_drag;
          delete n.__frozen_prev_fx;
          delete n.__frozen_prev_fy;
        });
      } catch(e){}
    }
    const subnetG = subnetLayer.selectAll('g.subnet-group')
      .data(subnetGroups, d => d.cidr)
      .enter()
      .append('g')
      .attr('class', 'subnet-group');

    subnetG.append('rect')
      .attr('class', 'subnet-rect')
      .attr('rx', 10)
      .attr('ry', 10)
      .attr('fill', 'rgba(255,255,255,0.58)')
      .attr('stroke', '#2b2b2b')
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', '6,4');

    subnetG.append('text')
      .attr('class', 'subnet-label')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .attr('fill', '#1f1f1f')
      .text(d => d.cidr);

    const link = g.selectAll('line.link')
      .data(links)
      .enter().append('line')
      .attr('class','link')
      .attr('stroke','#999')
      .attr('stroke-opacity',0.6)
      .attr('stroke-width',1.4);

    const nodeGroup = g.selectAll('g.node')
      .data(nodes)
      .enter().append('g')
      .attr('class', d => {
        const classes = ['node'];
        const typeVal = nodeTypeNormalized(d);
        if(typeVal === 'switch'){ classes.push('switch-node'); }
        if(nodeIsDocker(d)){ classes.push('docker-node'); }
        if(typeVal === 'host' || typeVal === 'pc' || typeVal === 'server'){
          classes.push('host-node');
          if(nodeHasVulnerabilities(d)) classes.push('vuln-host-node');
          else classes.push('plain-host-node');
        }
        if(nodeIsHitl(d)){ classes.push('hitl-node'); }
        return classes.join(' ');
      })
      .style('cursor','pointer')
      .call(d3.drag()
        .on('start', (ev,d)=>{
          // Prevent the svg zoom/pan handler from also acting on this gesture.
          // Without this, dragging a node can simultaneously pan the whole graph,
          // which feels like the layout is "going haywire".
          try {
            if(ev && ev.sourceEvent){
              if(typeof ev.sourceEvent.preventDefault === 'function') ev.sourceEvent.preventDefault();
              if(typeof ev.sourceEvent.stopImmediatePropagation === 'function') ev.sourceEvent.stopImmediatePropagation();
              if(typeof ev.sourceEvent.stopPropagation === 'function') ev.sourceEvent.stopPropagation();
            }
          } catch(e) {}
          // Non-destructive drag: allow moving while held, but snap back on drop.
          // Freeze subnet boxes while dragging so boxes don't resize/shift.
          try {
            // Ensure subnet boxes have cached bounds before we freeze them.
            if(typeof updateSubnetBoxes === 'function') updateSubnetBoxes();
          } catch(e) {}

          try {
            d.__dragging = true;
            __activeDragCount += 1;
            if(__activeDragCount === 1){
              _freezeOtherNodes(d);
            }
          } catch(e) {}

          d.__drag_origin = {
            x: (Number.isFinite(d.x) ? d.x : null),
            y: (Number.isFinite(d.y) ? d.y : null),
            fx: (Number.isFinite(d.fx) ? d.fx : null),
            fy: (Number.isFinite(d.fy) ? d.fy : null),
          };

          // Ensure ticks keep flowing while dragging (if the sim had cooled/stopped,
          // otherwise fx/fy updates may not visibly move the node).
          try {
            if(!ev.active){
              simulation.alphaTarget(0.18).restart();
            }
          } catch(e) {}

          // Keep pinned during drag, using graph-space coords (accounts for zoom/pan).
          d.fx = d.x;
          d.fy = d.y;
          try { updatePositions(); } catch(e) {}
        })
        .on('drag', (ev,d)=>{
          try {
            if(ev && ev.sourceEvent){
              if(typeof ev.sourceEvent.preventDefault === 'function') ev.sourceEvent.preventDefault();
              if(typeof ev.sourceEvent.stopImmediatePropagation === 'function') ev.sourceEvent.stopImmediatePropagation();
              if(typeof ev.sourceEvent.stopPropagation === 'function') ev.sourceEvent.stopPropagation();
            }
          } catch(e) {}
          // Always keep the node under the pointer while dragging.
          // Convert pointer to graph coordinates so dragging works correctly under zoom/pan.
          try {
            const pt = d3.pointer(ev.sourceEvent || ev, svg.node());
            const t = d3.zoomTransform(svg.node());
            const inv = t && typeof t.invert === 'function' ? t.invert(pt) : pt;
            d.fx = inv[0];
            d.fy = inv[1];
            // Also move the node immediately so it renders even if the simulation is idle.
            d.x = d.fx;
            d.y = d.fy;
          } catch(e) {
            d.fx = ev.x;
            d.fy = ev.y;
            d.x = d.fx;
            d.y = d.fy;
          }
          try { updatePositions(); } catch(e) {}
        })
        .on('end', (ev,d)=>{
          try {
            // Snap back to where the node originated. Do not create new pins.
            const o = d.__drag_origin || {};
            if(Number.isFinite(o.x)) d.x = o.x;
            if(Number.isFinite(o.y)) d.y = o.y;
            if(Number.isFinite(o.fx) && Number.isFinite(o.fy)){
              d.fx = o.fx;
              d.fy = o.fy;
            } else {
              d.fx = null;
              d.fy = null;
            }
            d.__pinned_by_drag = false;
          } catch(e) {}
          try {
            delete d.__drag_origin;
            d.__dragging = false;
            __activeDragCount = Math.max(0, (__activeDragCount || 0) - 1);
            if(__activeDragCount === 0){
              _unfreezeOtherNodes();
            }
          } catch(e) {}
          try { updatePositions(); } catch(e) {}
          if(!ev.active) simulation.alphaTarget(0);
        })
      );

    const rects = nodeGroup.append('rect')
      .attr('width', d => boxW(d))
      .attr('height', d => boxH(d))
      .attr('x', d => -(boxW(d)) / 2)
      .attr('y', d => -(boxH(d)) / 2)
      .attr('rx',6).attr('ry',6)
      .attr('fill', d => nodeFillColor(d))
      .attr('stroke', d => {
        const seq = nodeSequenceIndex(d);
        if(seq) return sequenceColor;
        return '#222';
      })
      .attr('stroke-width', d => {
        const seq = nodeSequenceIndex(d);
        if(seq) return 3;
        return 1.2;
      })
      .attr('stroke-dasharray', d => {
        try {
          // Distinguish docker nodes from other vulnerable nodes.
          return nodeIsDocker(d) ? '6,4' : null;
        } catch(e){
          return null;
        }
      })
      .on('click', (ev,d)=>{
        // Do not toggle pin/unpin on click; it can destabilize the layout.
        // Expand accordion section for this node if present
        try {
          const accItem = document.querySelector(`.accordion-item[data-node-id="${CSS.escape(String(d.id))}"]`);
          if(accItem){
            const collapse = accItem.querySelector('.accordion-collapse');
            if(collapse && !collapse.classList.contains('show')) {
              new bootstrap.Collapse(collapse, {toggle: true});
            }
            accItem.scrollIntoView({behavior:'smooth', block:'start'});
            // Flash highlight class
            accItem.classList.remove('flash-highlight'); // restart animation if re-clicked
            // Force reflow to allow animation restart
            void accItem.offsetWidth;
            accItem.classList.add('flash-highlight');
            setTimeout(()=> accItem.classList.remove('flash-highlight'), 2000);
          }
        } catch(e){}
      })
      .on('mouseover', (ev,d)=> highlightNeighbors(d,true))
      .on('mouseout', (ev,d)=> highlightNeighbors(d,false));

    // Tooltip
    const tooltipEl = document.getElementById('graphTooltip');
    let tooltipTimer = null;
    function showTooltip(d, x, y){
      if(!tooltipEl) return;
      const svcList = (d.services||[]);
      const ifaceList = Array.isArray(d.interfaces) ? d.interfaces : [];
      const lines = [];
      lines.push(`<strong>${(displayNameWithSequence(d)||'')} (${d.id})</strong>`);
      if(svcList.length){
        svcList.forEach(s => lines.push(s));
      } else {
        lines.push('<em>No Services</em>');
      }
      if(ifaceList.length){
        lines.push('<span class="text-muted">Interfaces</span>');
        ifaceList.slice(0, 4).forEach(iface => {
          const parts = [];
          if(iface.name){ parts.push(iface.name); }
          if(iface.mac){ parts.push(iface.mac); }
          const addrParts = [];
          if(!nodeIsHitl(d)){
            if(iface.ipv4){ addrParts.push(`${iface.ipv4}${iface.ipv4_mask ? '/' + iface.ipv4_mask : ''}`); }
            if(iface.ipv6){ addrParts.push(`${iface.ipv6}${iface.ipv6_mask ? '/' + iface.ipv6_mask : ''}`); }
          }
          if(addrParts.length){ parts.push(addrParts.join(' | ')); }
          if(parts.length){ lines.push(parts.join(' • ')); }
        });
        if(ifaceList.length > 4){
          lines.push(`(+${ifaceList.length - 4} more)`);
        }
      }
      tooltipEl.innerHTML = lines.join('<br>');
      tooltipEl.classList.remove('hidden');
      positionTooltip(x,y);
    }
    function hideTooltip(){ if(!tooltipEl) return; tooltipEl.classList.add('hidden'); }
    function positionTooltip(px,py){ if(!tooltipEl) return; const offX = px + 14; const offY = py + 14; tooltipEl.style.left = offX + 'px'; tooltipEl.style.top = offY + 'px'; }

    rects.on('mouseover.tooltip', (ev,d)=>{ if(tooltipTimer) clearTimeout(tooltipTimer); const [mx,my] = d3.pointer(ev, container); tooltipTimer = setTimeout(()=> showTooltip(d,mx,my), 500); })
      .on('mousemove.tooltip', (ev,d)=>{ if(!tooltipEl || tooltipEl.classList.contains('hidden')) return; const [mx,my]=d3.pointer(ev, container); positionTooltip(mx,my); })
      .on('mouseout.tooltip', ()=>{ if(tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer=null; } hideTooltip(); });

    // Labels: do not truncate with ellipses; keep full text.
    function wrapLabel(name){ return name ? String(name) : ''; }

    // Sequence index marker (Roman numerals) for sequence nodes.
    // Mirrors Preview tab graph view behavior.
    const seqBadgeWidth = (d) => {
      const seq = nodeSequenceIndex(d);
      const roman = toRoman(seq);
      const w = 10 + Math.max(1, String(roman || '').length) * 7;
      return Math.min(46, Math.max(18, w));
    };
    const seqBadge = nodeGroup.append('g')
      .attr('class','node-seq-badge')
      .attr('pointer-events','none')
      .style('display', d => nodeSequenceIndex(d) ? null : 'none');
    seqBadge.attr('transform', d => {
      const w = boxW(d);
      const h = boxH(d);
      const bx = (w / 2) + 6;
      const by = -(h / 2) - 22;
      return `translate(${bx},${by})`;
    });
    seqBadge.append('rect')
      .attr('x', 0)
      .attr('y', 0)
      .attr('width', d => seqBadgeWidth(d))
      .attr('height', 16)
      .attr('rx', 4)
      .attr('ry', 4)
      .attr('fill', '#fff')
      .attr('stroke', sequenceColor)
      .attr('stroke-width', 2);
    seqBadge.append('text')
      .attr('class','node-seq-badge-text')
      .attr('text-anchor','start')
      .attr('x', 5)
      .attr('y', 12)
      .attr('font-size','11px')
      .attr('font-weight','800')
      .attr('fill', sequenceColor)
      .text(d => {
        const seq = nodeSequenceIndex(d);
        return seq ? toRoman(seq) : '';
      });

    nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y',-2)
      .attr('font-size','10px')
      .attr('pointer-events','none')
      .attr('fill', d => labelFill(d))
      .attr('class','label')
      .text(d => wrapLabel(displayNameWithSequence(d)||''));

    // Explicit HITL callout label.
    const hereLabel = nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y', d => nodeIsHitl(d) ? (-(boxH(d) / 2) - 10) : ((boxH(d) / 2) + 18))
      .attr('font-size','14px')
      .attr('font-weight','700')
      .attr('pointer-events','none')
      .attr('fill', d => labelFill(d))
      .attr('stroke', d => nodeIsHitl(d) ? '#fff' : 'none')
      .attr('stroke-width', d => nodeIsHitl(d) ? 3 : 0)
      .attr('paint-order', 'stroke')
      .attr('class','here-label')
      .text(d => nodeIsHitl(d) ? 'YOU ARE HERE' : '');

    // Flash the HITL callout for ~5 seconds.
    try {
      hereLabel.filter(d => nodeIsHitl(d)).classed('here-label-flash', true);
      setTimeout(()=>{
        try { hereLabel.filter(d => nodeIsHitl(d)).classed('here-label-flash', false); } catch(e){}
      }, 5000);
    } catch(e){}

    nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y',12)
      .attr('font-size','8px')
      .attr('pointer-events','none')
      .attr('fill','#000')
      .text(d => (d.services||[]).length>0 ? (d.services||[]).length : '');

    // Primary IPv4 (kept compact; full detail remains in tooltip)
    nodeGroup.append('text')
      .attr('text-anchor','middle')
      .attr('y',24)
      .attr('font-size','8px')
      .attr('pointer-events','none')
      .attr('fill', d => labelFill(d))
      .text(d => {
        if(nodeIsHitl(d)) return '';
        const ip = primaryIpv4(d);
        return ip ? ip : '';
      });

    function highlightNeighbors(d, on){
      const neighborSet = new Set();
      links.forEach(l => { if(l.source.index===d.index) neighborSet.add(l.target.index); if(l.target.index===d.index) neighborSet.add(l.source.index); });
      nodeGroup.classed('fade', n => on && n.index!==d.index && !neighborSet.has(n.index));
      link.classed('highlight', l => on && (l.source.index===d.index || l.target.index===d.index));
      if(!on){ nodeGroup.classed('fade', false); link.classed('highlight', false);} }

    // Legend builder (optional external container with id graphLegendItems)
    const legendEl = document.getElementById('graphLegendItems');
    if(legendEl){
      const degreePerType = new Map();
      links.forEach(l=>{
        const inc=(idx)=>{
          const cat=nodeCategory(nodes[idx]);
          if(!cat) return;
          const s=degreePerType.get(cat)||0;
          degreePerType.set(cat,s+1);
        };
        inc(l.source.index??l.source);
        inc(l.target.index??l.target);
      });
      const types = Array.from(new Set(nodes.map(n => nodeCategory(n)))).filter(Boolean).sort();
      const hasSequenceNodes = nodes.some(n => nodeSequenceIndex(n));
      const hasVulnerableHosts = nodes.some(n => {
        const t = nodeTypeNormalized(n);
        if(!(t === 'host' || t === 'pc' || t === 'server')) return false;
        return nodeHasVulnerabilities(n);
      });
      let legendHtml = types.map(typeKey => {
        const nodeCount = nodes.filter(n => nodeCategory(n)===typeKey).length;
        const deg = degreePerType.get(typeKey)||0;
        const isSwitch = typeKey === 'switch';
        const colorSwatch = typeKey==='hitl' ? hitlColor : typeColor(typeKey);
        const isDocker = typeKey === 'docker';
        const swatchStyle = isSwitch
          ? `display:inline-block;width:12px;height:12px;border:2px solid #ff9800;background:${colorSwatch};box-shadow:0 0 0 1px #222 inset;`
          : (isDocker
            ? `display:inline-block;width:12px;height:12px;border:2px dashed #222;background:${colorSwatch}`
            : `display:inline-block;width:12px;height:12px;border:1px solid #222;background:${colorSwatch}`);
        const label = typeKey === 'hitl' ? 'HITL' : typeKey;
        return `<span class="d-flex align-items-center gap-1"><span style="${swatchStyle}"></span>${label}<span class="text-muted" style="font-size:.65rem;">(nodes:${nodeCount}, links:${deg})</span></span>`;
      }).join(' ');

      if(hasSequenceNodes){
        const seqBadge = `<span style="display:inline-flex;align-items:center;justify-content:center;width:18px;height:16px;border:2px solid ${sequenceColor};border-radius:4px;background:#fff;color:${sequenceColor};font-size:11px;font-weight:800;line-height:1;">I</span>`;
        const seqItem = `<span class="d-flex align-items-center gap-1">${seqBadge}Sequence</span>`;
        legendHtml = legendHtml ? `${seqItem} ${legendHtml}` : seqItem;
      }
      if(hasVulnerableHosts){
        const vulnSwatch = `<span class="d-flex align-items-center gap-1"><span style="display:inline-block;width:12px;height:12px;border:1px solid #222;background:${vulnerabilityColor}"></span>host (vulnerable)</span>`;
        legendHtml = legendHtml ? `${legendHtml} ${vulnSwatch}` : vulnSwatch;
      }
      legendEl.innerHTML = legendHtml;
    }

  simulation.on('tick', () => { updatePositions(); });

    function packDisjointSubnetGroups(){
      if(!subnetGroups || subnetGroups.length < 2) return;

      // Disjoint means each node belongs to at most one drawn subnet group.
      const membership = new Array(nodes.length).fill(0);
      subnetGroups.forEach(g => {
        (g.idxs || []).forEach(i => { if(typeof i === 'number') membership[i] += 1; });
      });
      const disjoint = membership.every(c => c <= 1);
      if(!disjoint) return;

      // Compute current bounds for each group.
      const pad = 26;
      const bounds = [];
      subnetGroups.forEach(g => {
        const idxs = g.idxs || [];
        if(!idxs.length) return;
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        idxs.forEach(i => {
          const n = nodes[i];
          if(!n || n.x == null || n.y == null) return;
          const w = boxW(n);
          const h = boxH(n);
          minX = Math.min(minX, n.x - w/2);
          maxX = Math.max(maxX, n.x + w/2);
          minY = Math.min(minY, n.y - h/2);
          maxY = Math.max(maxY, n.y + h/2);
        });
        if(!Number.isFinite(minX) || !Number.isFinite(minY)) return;
        minX -= pad; minY -= pad;
        maxX += pad; maxY += pad;
        const cx = (minX + maxX) / 2;
        bounds.push({ cidr: g.cidr, idxs: idxs.slice(), minX, maxX, minY, maxY, cx, w: (maxX - minX) });
      });
      if(bounds.length < 2) return;

      // Prefer ordering by precomputed subnet lane center if available, else current center.
      bounds.sort((a,b)=> {
        const ax = subnetCenterX.get(a.cidr) ?? a.cx;
        const bx = subnetCenterX.get(b.cidr) ?? b.cx;
        return ax - bx;
      });

      const gap = 70; // explicit space between subnet boxes
      const viewW = container.clientWidth || width;

      // First pass: pack left-to-right starting at x=0.
      let cursor = 0;
      bounds.forEach(b => {
        const desiredMinX = cursor;
        const dx = desiredMinX - b.minX;
        if(Math.abs(dx) > 0.01){
          b.idxs.forEach(i => {
            const n = nodes[i];
            if(!n) return;
            if(n.x != null) n.x += dx;
            if(n.fx != null) n.fx += dx;
          });
          b.minX += dx; b.maxX += dx; b.cx += dx;
        }
        cursor = b.maxX + gap;
      });

      // Second pass: center the packed span within the viewport.
      const span = (cursor - gap);
      const shift = (viewW / 2) - (bounds[0].minX + span / 2);
      if(Number.isFinite(shift) && Math.abs(shift) > 0.01){
        bounds.forEach(b => {
          b.idxs.forEach(i => {
            const n = nodes[i];
            if(!n) return;
            if(n.x != null) n.x += shift;
            if(n.fx != null) n.fx += shift;
          });
        });
      }
    }

    function _nodeX(ref){
      if(ref && typeof ref === 'object' && Number.isFinite(ref.x)) return ref.x;
      if(typeof ref === 'number' && nodes[ref] && Number.isFinite(nodes[ref].x)) return nodes[ref].x;
      if(ref && typeof ref === 'object' && typeof ref.index === 'number' && nodes[ref.index] && Number.isFinite(nodes[ref.index].x)) return nodes[ref.index].x;
      return 0;
    }
    function _nodeY(ref){
      if(ref && typeof ref === 'object' && Number.isFinite(ref.y)) return ref.y;
      if(typeof ref === 'number' && nodes[ref] && Number.isFinite(nodes[ref].y)) return nodes[ref].y;
      if(ref && typeof ref === 'object' && typeof ref.index === 'number' && nodes[ref.index] && Number.isFinite(nodes[ref.index].y)) return nodes[ref.index].y;
      return 0;
    }

    function updatePositions(){
      // Packing subnet groups on every tick works well for a static layout,
      // but it fights interactive drags (it can shift entire subnet groups while
      // the user is trying to move a single node).
      if((__activeDragCount || 0) === 0){
        packDisjointSubnetGroups();
      }
      link
        .attr('x1', d => _nodeX(d.source))
        .attr('y1', d => _nodeY(d.source))
        .attr('x2', d => _nodeX(d.target))
        .attr('y2', d => _nodeY(d.target));
      nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
      updateSubnetBoxes();
      // While dragging, keep all other nodes static.
      if((__activeDragCount || 0) === 0){
        pushRoutersOutOfSubnetBoxes();
      }
    }

    function pushRoutersOutOfSubnetBoxes(){
      try {
        if(!subnetGroups || subnetGroups.length === 0) return;
        // Keep routers clearly outside subnet boxes with some clearance so they don't
        // appear "in" a box or touching its border.
        const clearance = 22;
        const boxes = [];
        subnetGroups.forEach(g => {
          if(g && g.__bounds && Number.isFinite(g.__bounds.minX) && Number.isFinite(g.__bounds.minY)){
            boxes.push({
              minX: g.__bounds.minX - clearance,
              minY: g.__bounds.minY - clearance,
              maxX: g.__bounds.maxX + clearance,
              maxY: g.__bounds.maxY + clearance,
            });
          }
        });
        if(!boxes.length) return;

        const routers = nodes.filter(n => nodeTier(n) === 0);
        routers.forEach(r => {
          if(!r || !Number.isFinite(r.x) || !Number.isFinite(r.y)) return;
          const halfW = boxW(r) / 2;
          const halfH = boxH(r) / 2;

          // A router might overlap multiple boxes; resolve a few times.
          for(let iter = 0; iter < 3; iter++){
            let moved = false;
            for(const b of boxes){
              const rMinX = r.x - halfW;
              const rMaxX = r.x + halfW;
              const rMinY = r.y - halfH;
              const rMaxY = r.y + halfH;
              const overlapX = !(rMaxX < b.minX || rMinX > b.maxX);
              const overlapY = !(rMaxY < b.minY || rMinY > b.maxY);
              if(!overlapX || !overlapY) continue;

              const candidates = [
                { x: (b.minX - halfW - 2), y: r.y },
                { x: (b.maxX + halfW + 2), y: r.y },
                { x: r.x, y: (b.minY - halfH - 2) },
                { x: r.x, y: (b.maxY + halfH + 2) },
              ];
              candidates.sort((a,b2)=> (Math.hypot(a.x - r.x, a.y - r.y)) - (Math.hypot(b2.x - r.x, b2.y - r.y)));
              const best = candidates[0];
              if(best && Number.isFinite(best.x) && Number.isFinite(best.y)){
                r.x = best.x;
                r.y = best.y;
                if(r.fx != null) r.fx = best.x;
                if(r.fy != null) r.fy = best.y;
                moved = true;
              }
            }
            if(!moved) break;
          }
        });
      } catch(e) {}
    }

    function updateSubnetBoxes(){
      if(!subnetGroups || subnetGroups.length === 0) return;
      const pad = 26;
      subnetG.each(function(d){
        const idxs = d.idxs || [];
        if(!idxs.length) return;
        // While dragging, keep subnet rectangle bounds stable.
        const freeze = ((__activeDragCount || 0) > 0);
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        if(!freeze){
          idxs.forEach(i => {
            const n = nodes[i];
            if(!n || n.x == null || n.y == null) return;
            const w = boxW(n);
            const h = boxH(n);
            minX = Math.min(minX, n.x - w/2);
            maxX = Math.max(maxX, n.x + w/2);
            minY = Math.min(minY, n.y - h/2);
            maxY = Math.max(maxY, n.y + h/2);
          });
          if(!Number.isFinite(minX) || !Number.isFinite(minY)) return;
          minX -= pad; minY -= pad;
          maxX += pad; maxY += pad;
          d.__bounds = { minX, minY, maxX, maxY };
        } else if(d.__bounds && Number.isFinite(d.__bounds.minX) && Number.isFinite(d.__bounds.minY)){
          minX = d.__bounds.minX;
          minY = d.__bounds.minY;
          maxX = d.__bounds.maxX;
          maxY = d.__bounds.maxY;
        } else {
          // No cached bounds yet; fall back to computing once.
          idxs.forEach(i => {
            const n = nodes[i];
            if(!n || n.x == null || n.y == null) return;
            const w = boxW(n);
            const h = boxH(n);
            minX = Math.min(minX, n.x - w/2);
            maxX = Math.max(maxX, n.x + w/2);
            minY = Math.min(minY, n.y - h/2);
            maxY = Math.max(maxY, n.y + h/2);
          });
          if(!Number.isFinite(minX) || !Number.isFinite(minY)) return;
          minX -= pad; minY -= pad;
          maxX += pad; maxY += pad;
          d.__bounds = { minX, minY, maxX, maxY };
        }

        const w = Math.max(40, maxX - minX);
        const h = Math.max(40, maxY - minY);
        const sel = d3.select(this);
        sel.select('rect.subnet-rect')
          .attr('x', minX)
          .attr('y', minY)
          .attr('width', w)
          .attr('height', h);
        sel.select('text.subnet-label')
          .attr('x', minX + 10)
          .attr('y', minY + 16);
      });
    }
    // (Grid layout removal: updateLinksStatic no longer needed)

    // Public controls hooking (if buttons exist)
    const resetBtn = document.getElementById('graphResetBtn');
    const clusterBtn = document.getElementById('graphClusterBtn');
    const exportSvgBtn = document.getElementById('graphExportSvgBtn');
    const exportPngBtn = document.getElementById('graphExportPngBtn');
    resetBtn?.addEventListener('click', () => { svg.transition().duration(400).call(zoomBehavior.transform, d3.zoomIdentity); nodes.forEach(n=>{ n.fx=null; n.fy=null; }); simulation.alpha(0.5).restart(); });

    function _resetLayoutImmediate(){
      try {
        svg.interrupt();
        svg.call(zoomBehavior.transform, d3.zoomIdentity);
      } catch(e){}
      try {
        nodes.forEach(n=>{
          n.fx = null;
          n.fy = null;
          n.__pinned_by_drag = false;
        });
      } catch(e){}
      try {
        simulation.alpha(0.5).restart();
      } catch(e){}
      try { updatePositions(); } catch(e){}
    }

  clusterBtn?.addEventListener('click', () => { if(clusterMode==='off') { clusterMode='type'; clusterBtn.textContent='Cluster: Type'; applyClustering(); } else { clusterMode='off'; clusterBtn.textContent='Cluster: Off'; simulation.force('x', null).force('y', null); simulation.alpha(0.5).restart(); } });

    function applyClustering(){
      const types = Array.from(new Set(nodes.map(n => nodeCategory(n)))).filter(Boolean);
      if(!types.length) return; const angleStep = (2*Math.PI)/types.length; const radius = Math.min(width,height)/3; const centers = new Map();
      types.forEach((t,i)=> centers.set(t,{x: Math.cos(i*angleStep)*radius, y: Math.sin(i*angleStep)*radius}));
      simulation.force('x', d3.forceX(d => (centers.get(nodeCategory(d))||{x:0}).x + width/2).strength(0.12));
      simulation.force('y', d3.forceY(d => (centers.get(nodeCategory(d))||{y:0}).y + height/2).strength(0.12));
  simulation.alpha(0.9).restart();
    }

    exportSvgBtn?.addEventListener('click', exportSvg);
    exportPngBtn?.addEventListener('click', exportPng);

    // centerAndFit removed (Fit button no longer present)

    function serializeSvg(){
      const clone = svg.node().cloneNode(true);
      clone.querySelectorAll('title').forEach(t => t.remove());
      const serializer = new XMLSerializer();
      let source = serializer.serializeToString(clone);
      if(!source.match(/^<svg[^>]+xmlns="http:\/\/www.w3.org\/2000\/svg"/)) source = source.replace('<svg','<svg xmlns="http://www.w3.org/2000/svg"');
      return source;
    }
    function exportSvg(){ const source = serializeSvg(); const blob = new Blob([source], {type:'image/svg+xml;charset=utf-8'}); const url = URL.createObjectURL(blob); triggerDownload(url, 'topology.svg'); setTimeout(()=> URL.revokeObjectURL(url), 1500); }
    function exportPng(){ const source = serializeSvg(); const img = new Image(); const svgBlob = new Blob([source], {type:'image/svg+xml;charset=utf-8'}); const url = URL.createObjectURL(svgBlob); img.onload = function(){ const canvas = document.createElement('canvas'); canvas.width = container.clientWidth * 2; canvas.height = container.clientHeight * 2; const ctx = canvas.getContext('2d'); ctx.fillStyle = '#ffffff'; ctx.fillRect(0,0,canvas.width,canvas.height); ctx.drawImage(img,0,0,canvas.width,canvas.height); URL.revokeObjectURL(url); canvas.toBlob(b => { const pngUrl = URL.createObjectURL(b); triggerDownload(pngUrl,'topology.png'); setTimeout(()=>URL.revokeObjectURL(pngUrl), 1500); }, 'image/png'); }; img.src = url; }
    function triggerDownload(url, filename){ const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); }

    // Mini-map
    const miniMap = document.getElementById('graphMiniMap');
    const miniSvg = miniMap ? d3.select(miniMap).select('svg'):null; let miniG, miniLinks, miniNodes, viewRect;
    if(miniSvg){ miniG = miniSvg.append('g'); miniLinks = miniG.selectAll('line').data(links).enter().append('line').attr('stroke','#bbb').attr('stroke-width',1); miniNodes = miniG.selectAll('circle').data(nodes).enter().append('circle').attr('r',2.8).attr('fill', d=>nodeFillColor(d)); viewRect = miniG.append('rect').attr('fill','none').attr('stroke','#ff5722').attr('stroke-width',1); miniMap.addEventListener('mousedown', (ev)=>{ ev.preventDefault(); const pt = d3.pointer(ev, miniG.node()); svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity.translate(container.clientWidth/2 - pt[0], container.clientHeight/2 - pt[1]).scale(1)); }); }
    function updateMiniMap(){ if(!miniSvg) return; const xs=nodes.map(n=>n.x), ys=nodes.map(n=>n.y); if(!xs.length) return; const minX=Math.min(...xs), maxX=Math.max(...xs), minY=Math.min(...ys), maxY=Math.max(...ys); const pad=40; const w=(maxX-minX)||1, h=(maxY-minY)||1; const scaleX=(160-pad)/w, scaleY=(120-pad)/h; const s=Math.min(scaleX, scaleY); const ox=(160 - w*s)/2, oy=(120 - h*s)/2; miniG.attr('transform', `translate(${ox - minX*s},${oy - minY*s}) scale(${s})`); miniLinks.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y); miniNodes.attr('cx',d=>d.x).attr('cy',d=>d.y); updateMiniMapViewport(d3.zoomTransform(svg.node())); }
    function updateMiniMapViewport(z){ if(!viewRect) return; try { const t=z||d3.zoomTransform(svg.node()); const inv=t.invert([0,0]); const inv2=t.invert([container.clientWidth, container.clientHeight]); viewRect.attr('x',inv[0]).attr('y',inv[1]).attr('width',inv2[0]-inv[0]).attr('height',inv2[1]-inv[1]); } catch(e){} }
  simulation.on('tick.graphExtras', ()=> { updateMiniMap(); });
    setInterval(()=> updateMiniMap(), 1500); updateMiniMap();

    // Stats
    const statsEl = document.getElementById('graphStats'); if(statsEl){ statsEl.textContent = `${nodes.length} nodes, ${links.length} links`; }

    // Resize handling
  const ro = new ResizeObserver(entries => {
    for(const e of entries){
      const w = e.contentRect.width;
      const h = e.contentRect.height;
      svg.attr('width', w).attr('height', h);
      placeHitlNodes(w, h);
      simulation.force('center', d3.forceCenter(w/2, h/2));
      simulation.alpha(0.15).restart();

      // If we initialized while hidden (e.g., inside a collapsed panel),
      // the first layout tends to be overly spaced; clicking Reset fixes it.
      // Do that automatically once when the container becomes visible.
      try {
        const wasHidden = (__initialContainerSize.w < 80 || __initialContainerSize.h < 80);
        const nowVisible = (w >= 160 && h >= 160);
        if(!__autoResetOnFirstShowDone && wasHidden && nowVisible){
          __autoResetOnFirstShowDone = true;
          _resetLayoutImmediate();
        }
      } catch(e){}
    }
  });
    ro.observe(container);

    // Persist positions on unload
    window.addEventListener('beforeunload', ()=> {
      try {
        const out = {};
        nodes.forEach(n => {
          const nx = Number(n.x);
          const ny = Number(n.y);
          out[n.id] = {
            x: Number.isFinite(nx) ? nx : null,
            y: Number.isFinite(ny) ? ny : null,
            // Back-compat field (not used for restore anymore)
            pinned: (n.fx != null || n.fy != null),
            // Only restore pins created via drag (avoids click-release pinning)
            pinned_by_drag: (n.__pinned_by_drag === true),
          };
        });
        localStorage.setItem(storageKey, JSON.stringify(out));
      } catch(e){}
    });

    return { exportSvg, exportPng, applyClustering, simulation, nodes, links };
  }
  window.CoreGraph = { init: initCoreGraph };
})(window, document, d3);
