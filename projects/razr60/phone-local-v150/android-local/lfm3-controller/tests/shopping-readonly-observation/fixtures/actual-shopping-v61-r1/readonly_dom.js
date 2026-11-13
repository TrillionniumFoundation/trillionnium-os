(function () {
  "use strict";
  // Fixed observer only: no click, input, submit, fetch, event dispatch, native
  // interface, storage mutation or page-installed callback. No model code is used.
  var maxVisited = 4096, maxRecords = 1536, maxText = 65536;
  var maxField = 4096, visited = 0, textUsed = 0, rows = [], reasons = [];
  var queue = [{node: document.documentElement, path: "0", parent: null}];
  var rawElements = Object.create(null), rawStyles = Object.create(null);
  var elementPaths = new WeakMap();
  function observeStyle(n, style, path) {
    function property(name) { return String(style.getPropertyValue(name)); }
    function pseudo(name) {
      var p = window.getComputedStyle(n, name);
      return {content: String(p.content), display: String(p.display), position: String(p.position),
        visibility: String(p.visibility), opacity: String(p.opacity), transform: String(p.transform),
        pointer_events: String(p.pointerEvents)};
    }
    return {path: path, position: property("position"), display: property("display"),
      visibility: property("visibility"), opacity: property("opacity"),
      overflow_x: property("overflow-x"), overflow_y: property("overflow-y"),
      overflow_clip_margin: property("overflow-clip-margin"),
      transform: property("transform"), translate: property("translate"), rotate: property("rotate"),
      scale: property("scale"), transform_style: property("transform-style"), zoom: property("zoom"),
      perspective: property("perspective"), filter: property("filter"), backdrop_filter: property("backdrop-filter"),
      clip_path: property("clip-path"), mask_image: property("mask-image"), contain: property("contain"),
      content_visibility: property("content-visibility"), will_change: property("will-change"),
      pointer_events: property("pointer-events"), isolation: property("isolation"), mix_blend_mode: property("mix-blend-mode"),
      element_child_count: n.childElementCount, accessible_shadow_root_present: n.shadowRoot !== null,
      closed_shadow_contents_inspected: false, pseudo_before: pseudo("::before"), pseudo_after: pseudo("::after")};
  }
  function inPath(rootPath, path) { return path === rootPath || path.indexOf(rootPath + "/") === 0; }
  function overlap(a, b) { return Math.max(a[0], b[0]) < Math.min(a[2], b[2]) && Math.max(a[1], b[1]) < Math.min(a[3], b[3]); }
  function miClipObservations() {
    var selected=rows.filter(function(n){return n.id==="J_miniCartMenu";}), contexts=[], candidates=[];
    var paths=Object.create(null);
    selected.forEach(function(n){
      var element=rawElements[n.path];
      candidates.push({path:n.path,id:n.id,tag:n.tag,rect_css_pixels:n.rect_css_pixels.slice(),
        client_width:element.clientWidth,client_height:element.clientHeight,client_left:element.clientLeft,client_top:element.clientTop});
      rows.forEach(function(r){if(inPath(n.path,r.path)||inPath(r.path,n.path))paths[r.path]=true;});
    });
    var keys=Object.keys(paths).sort();
    keys.slice(0,128).forEach(function(p){contexts.push(observeStyle(rawElements[p],rawStyles[p],p));});
    return {schema:"hepta.raw-clip-context-observations.v1",candidates:candidates,style_contexts:contexts,
      complete:keys.length<=128,total_context_count:keys.length,fully_clipped_inferred:false,
      closed_shadow_contents_inspected:false,grants_action_authority:false};
  }
  function miRegion() {
    var observation = {schema: "hepta.mi-search-card-observations.v1", site_policy_id: "mi_cn_ax3000t_read_v2",
      selection: "fixed_AX3000T_white_observed_link_parent_card_v1", status: "not_applicable", candidate_count: 0,
      candidate: null, style_contexts: [], hit_tests: [], foreign_overlap_paths: [], visible_modal_paths: [],
      special_paint_in_region_paths: [], top_layer: null, complete: true,
      coordinates_used_for_input: false, closed_shadow_contents_inspected: false, pixel_visibility_claimed: false};
    if (String(window.location.href) !== "https://www.mi.com/shop/search?keyword=AX3000T") return observation;
    observation.status = "not_observed";
    var map = Object.create(null), candidates = [];
    rows.forEach(function (n) { map[n.path] = n; });
    function visible(n) { return n && n.visible_in_viewport === true && n.hidden_attr === false && n.inert_attr === false
      && n.disabled === false && n.aria_hidden !== "true"; }
    function underDeleted(path, stop) {
      for (var p = path; p && p !== stop; p = map[p] ? map[p].parent_path : null)
        if (map[p] && map[p].tag === "del") return true;
      return false;
    }
    rows.forEach(function (a) {
      if (a.tag !== "a" || !visible(a) || !a.parent_path || !map[a.parent_path] || map[a.parent_path].tag !== "div") return;
      if (!/^https:\/\/www\.mi\.com\/shop\/buy\?product_id=[1-9][0-9]{0,19}&cfrom=search$/.test(a.href_resolved || "")) return;
      if (a.link_target !== "_blank" && a.link_target !== "_self" && a.link_target !== "") return;
      try { if (new URL(a.href_raw, String(window.location.href)).href !== a.href_resolved) return; } catch (badURL) { return; }
      var names = [], current = [], struck = [], links = [], forbidden = false;
      rows.forEach(function (n) {
        if (!inPath(a.parent_path, n.path)) return;
        if (n.tag === "a") links.push(n);
        if (["button","input","select","textarea","iframe","frame","object","embed","canvas","video","svg"].indexOf(n.tag) >= 0
            || n.role === "button" || n.role === "dialog" || n.aria_modal === "true") forbidden = true;
        if (visible(n) && n.text === "Xiaomi路由器AX3000T 白色" && n.tag === "h2" && inPath(a.path,n.path)) names.push(n);
        if (visible(n) && n.tag === "span" && /^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,2})?元$/.test(n.text.trim()) && inPath(a.path,n.path)) {
          (underDeleted(n.path, a.path) ? struck : current).push(n);
        }
        if (visible(n) && /券|会员|补贴|定金|分期|每月|月供|预售|预约|满减|到手|折后|需登录|需领|秒杀|限时|首购|加入购物车|立即购买|下单|支付/.test(n.text)) forbidden = true;
      });
      if (forbidden || names.length !== 1 || current.length !== 1 || struck.length !== 1 || links.length !== 1) return;
      candidates.push({root_path:a.parent_path,anchor_path:a.path,model_path:names[0].path,
        current_price_path:current[0].path,comparison_price_path:struck[0].path,
        model_label:names[0].text,observed_variant:"白色",href_raw:a.href_raw,href_resolved:a.href_resolved,
        link_target:a.link_target,current_price_raw:current[0].text,comparison_price_raw:struck[0].text,
        price_context:"search_card_only",detail_price_verified:false});
    });
    observation.candidate_count = candidates.length;
    if (candidates.length !== 1) { observation.status = candidates.length ? "ambiguous" : "not_observed"; return observation; }
    var selected = candidates[0], card = map[selected.root_path], anchor = map[selected.anchor_path];
    observation.candidate = selected; observation.status = "observed";
    var relevant = rows.filter(function (n) { return inPath(selected.root_path,n.path) || inPath(n.path,selected.root_path); });
    if (relevant.length > 128) { observation.complete=false; observation.status="context_budget"; return observation; }
    relevant.forEach(function (n) { observation.style_contexts.push(observeStyle(rawElements[n.path],rawStyles[n.path],n.path)); });
    rows.forEach(function (n) {
      if (visible(n) && (n.tag === "dialog" || n.role === "dialog" || n.role === "alertdialog" || n.aria_modal === "true"))
        observation.visible_modal_paths.push(n.path);
      if (!visible(n) || !overlap(n.rect_css_pixels,card.rect_css_pixels)) return;
      if (!inPath(selected.root_path,n.path) && !inPath(n.path,selected.root_path)) observation.foreign_overlap_paths.push(n.path);
      if (inPath(selected.root_path,n.path) && ["iframe","frame","object","embed","canvas","video","svg"].indexOf(n.tag)>=0)
        observation.special_paint_in_region_paths.push(n.path);
    });
    function observedPaths(selector) {
      var nodes=document.querySelectorAll(selector), paths=[];
      for(var k=0;k<nodes.length;k++){var p=elementPaths.get(nodes[k]);paths.push(p===undefined?null:p);}
      return paths;
    }
    try {
      var full=document.fullscreenElement;
      observation.top_layer={selector_api_available:true,modal_paths:observedPaths(":modal"),
        popover_paths:observedPaths(":popover-open"),fullscreen_present:full!==null,
        fullscreen_path:full===null?null:(elementPaths.get(full)||null),closed_shadow_contents_inspected:false};
    } catch (unsupportedSelector) {
      observation.top_layer={selector_api_available:false,modal_paths:[],popover_paths:[],
        fullscreen_present:document.fullscreenElement!==null,fullscreen_path:null,closed_shadow_contents_inspected:false};
      observation.complete=false;
    }
    [selected.anchor_path,selected.model_path,selected.current_price_path,selected.comparison_price_path].forEach(function (p) {
      var r=map[p].rect_css_pixels, points=[];
      [[0.5,0.5],[0.2,0.2],[0.8,0.2],[0.2,0.8],[0.8,0.8]].forEach(function (ratio) {
        var x=r[0]+(r[2]-r[0])*ratio[0], y=r[1]+(r[3]-r[1])*ratio[1];
        if (!(r[2]>r[0]&&r[3]>r[1]&&r[0]>=0&&r[1]>=0&&r[2]<=vw&&r[3]<=vh)) observation.complete=false;
        var top=document.elementFromPoint(x,y), stack=document.elementsFromPoint(x,y), paths=[], allKnown=stack.length<=64;
        for(var z=0;z<Math.min(stack.length,64);z++){var sp=elementPaths.get(stack[z]);if(sp===undefined)allKnown=false;paths.push(sp===undefined?null:sp);}
        var tp=top===null?null:elementPaths.get(top);
        points.push({x:x,y:y,top_path:tp===undefined?null:tp,stack_paths:paths,stack_complete:allKnown});
      });
      observation.hit_tests.push({dom_path:p,rect_css_pixels:r.slice(),points:points});
    });
    return observation;
  }
  var vw = window.innerWidth, vh = window.innerHeight;
  var vv = window.visualViewport;
  var visual = vv ? {width: vv.width, height: vv.height,
    offset_left: vv.offsetLeft, offset_top: vv.offsetTop,
    page_left: vv.pageLeft, page_top: vv.pageTop, scale: vv.scale} : null;
  var root = document.documentElement, meta = document.querySelector('meta[name="viewport"]');
  function reason(s) { if (reasons.indexOf(s) < 0) reasons.push(s); }
  function bounded(s) {
    s = String(s == null ? "" : s);
    if (s.length > maxField) { reason("field_text_truncated"); s = s.slice(0, maxField); }
    if (textUsed + s.length > maxText) {
      reason("total_text_budget"); s = s.slice(0, Math.max(0, maxText - textUsed));
    }
    textUsed += s.length;
    return s;
  }
  for (var cursor = 0; cursor < queue.length; cursor++) {
    if (visited >= maxVisited || rows.length >= maxRecords) { reason("node_budget"); break; }
    var item = queue[cursor], n = item.node;
    if (!n || n.nodeType !== 1) continue;
    visited++;
    var r = n.getBoundingClientRect(), style = window.getComputedStyle(n);
    rawElements[item.path]=n; rawStyles[item.path]=style; elementPaths.set(n,item.path);
    var visible = style.display !== "none" && style.visibility !== "hidden"
        && style.visibility !== "collapse" && Number(style.opacity) > 0
        && r.width > 0 && r.height > 0 && r.right > 0 && r.bottom > 0
        && r.left < vw && r.top < vh;
    var own = "";
    if (visible) for (var t = 0; t < n.childNodes.length; t++) {
      if (n.childNodes[t].nodeType === 3) own += n.childNodes[t].nodeValue;
    }
    var tag = n.tagName.toLowerCase();
    var value = (visible && (tag === "input" || tag === "textarea" || tag === "select"))
        ? String(n.value) : null;
    // Passwords and other private field values are not part of a public query record.
    if (tag === "input" && String(n.type).toLowerCase() === "password") value = null;
    rows.push({path: item.path, parent_path: item.parent, tag: tag,
      id: bounded(n.id), role: bounded(n.getAttribute("role")),
      name: bounded(n.getAttribute("name")), aria_label: bounded(n.getAttribute("aria-label")),
      href_raw: tag === "a" && n.hasAttribute("href") ? bounded(n.getAttribute("href")) : null,
      href_resolved: tag === "a" && n.hasAttribute("href") ? bounded(n.href) : null,
      link_target: tag === "a" ? bounded(n.getAttribute("target")) : null,
      item_scope: n.hasAttribute("itemscope"), item_type: bounded(n.getAttribute("itemtype")),
      item_prop: bounded(n.getAttribute("itemprop")), hidden_attr: n.hasAttribute("hidden"),
      inert_attr: n.hasAttribute("inert"), aria_hidden: bounded(n.getAttribute("aria-hidden")),
      aria_modal: bounded(n.getAttribute("aria-modal")),
      aria_selected: bounded(n.getAttribute("aria-selected")),
      aria_checked: bounded(n.getAttribute("aria-checked")),
      aria_pressed: bounded(n.getAttribute("aria-pressed")),
      text: bounded(own), value: value === null ? null : bounded(value),
      disabled: n.disabled === true, aria_disabled: n.getAttribute("aria-disabled"),
      visible_in_viewport: visible,
      rect_css_pixels: [r.left, r.top, r.right, r.bottom],
      iframe_contents_read: false});
    // Real DOM ancestry, including invisible wrappers, is retained. An iframe
    // element is recorded but its independent document is never traversed.
    if (tag !== "iframe" && tag !== "frame") for (var i = 0; i < n.children.length; i++) {
      if (queue.length >= maxVisited) { reason("traversal_queue_budget"); break; }
      queue.push({node: n.children[i], path: item.path + "/" + i, parent: item.path});
    }
  }
  if (visited < queue.length) reason("unvisited_nodes");
  return JSON.stringify({schema: "hepta.fixed-top-document-dom.v4",
    href: String(window.location.href), origin: String(window.location.origin),
    ready_state: document.readyState,
    viewport_css_pixels: [vw, vh], device_pixel_ratio: window.devicePixelRatio,
    layout_viewport_css_pixels: [root ? root.clientWidth : null, root ? root.clientHeight : null],
    document_scroll_css_pixels: [window.scrollX, window.scrollY],
    document_extent_css_pixels: [root ? root.scrollWidth : null, root ? root.scrollHeight : null],
    viewport_meta_content: meta ? bounded(meta.getAttribute("content")) : null,
    visual_viewport: visual, geometry_semantics_verified: false,
    visited: visited, text_utf16_units: textUsed,
    truncated: reasons.length !== 0, truncation_reasons: reasons, nodes: rows,
    action_region_observations: miRegion(), clipping_context_observations: miClipObservations()});
})()
