// Initialize KaTeX auto-render on page content with CSP-friendly external script
(function(){
  function safeContainer(el){
    return !(el.closest('pre, code'));
  }
  function tokenizeMath(text){
    var tokens = [];
    var i = 0;
    var dels = [
      {l:'$$', r:'$$', d:true},
      {l:'\\[', r:'\\]', d:true},
      {l:'\\(', r:'\\)', d:false},
      {l:'$', r:'$', d:false},
    ];
    while (i < text.length){
      // find earliest delimiter occurrence
      var best = null, bestIdx = -1;
      for (var di=0; di<dels.length; di++){
        var idx = text.indexOf(dels[di].l, i);
        if (idx !== -1 && (bestIdx === -1 || idx < bestIdx)) { best = dels[di]; bestIdx = idx; }
      }
      if (bestIdx === -1){
        tokens.push({t:'t', s:text.slice(i)});
        break;
      }
      if (bestIdx > i){ tokens.push({t:'t', s:text.slice(i, bestIdx)}); }
      var start = bestIdx + best.l.length;
      var end = text.indexOf(best.r, start);
      if (end === -1){
        // unmatched: treat as text
        tokens.push({t:'t', s:text.slice(bestIdx)});
        break;
      }
      var content = text.slice(start, end);
      tokens.push({t:'m', d:best.d, s:content});
      i = end + best.r.length;
    }
    return tokens;
  }
  function escapeUnderscoresInTextCommand(str){
    return str.replace(/\\text\{([^}]*)\}/g, function(_, inner){
      var out = '';
      for (var i=0;i<inner.length;i++){
        var ch = inner[i];
        if (ch === '_' && (i===0 || inner[i-1] !== '\\')){ out += '\\\\_'; }
        else { out += ch; }
      }
      return '\\text{' + out + '}';
    });
  }
  function rebuildWithKatex(el){
    if (!window.katex) return;
    var txt = el.textContent;
    if (!(/[\$]/.test(txt) || /\\\(|\\\)|\\\[|\\\]/.test(txt))) return;
    var tokens = tokenizeMath(txt);
    var hasMath = tokens.some(function(x){return x.t==='m';});
    if (!hasMath) {
      var trimmed = txt.trim();
      // If content uses double backslashes (e.g., \\text), normalise to single backslash for KaTeX
      var normalised = trimmed.replace(/\\\\/g, "\\");
      if (/\\\\?[a-zA-Z]+/.test(trimmed) || /\\[a-zA-Z]+/.test(normalised)) {
        // Try to render whole node as inline math when it looks like TeX but lacks delimiters
        try {
          var span = document.createElement('span');
          window.katex.render(escapeUnderscoresInTextCommand(normalised), span, {displayMode:false, strict:'ignore'});
          while (el.firstChild) el.removeChild(el.firstChild);
          el.appendChild(span);
          el.setAttribute('data-katex-rebuilt','1');
        } catch (_) {}
      }
      return;
    }
    while (el.firstChild) el.removeChild(el.firstChild);
    tokens.forEach(function(tok){
      if (tok.t==='t'){
        el.appendChild(document.createTextNode(tok.s));
      } else if (tok.t==='m'){
        var content = escapeUnderscoresInTextCommand(tok.s);
        var span = document.createElement('span');
        try { window.katex.render(content, span, {displayMode: tok.d, strict: "ignore"}); } catch(_) { span.textContent = tok.s; }
        el.appendChild(span);
      }
    });
    el.setAttribute('data-katex-rebuilt','1');
  }
  function init(){
    if (typeof renderMathInElement === 'function') {
      try {
        renderMathInElement(document.body, {
          delimiters: [
            {left: "$$", right: "$$", display: true},
            {left: "\\(", right: "\\)", display: false},
            {left: "\\[", right: "\\]", display: true}
          ],
          ignoredTags: ["script","noscript","style","textarea","pre","code","option"],
          preProcess: function (s) { return escapeUnderscoresInTextCommand(s); },
          errorCallback: function () { /* suppress autorender errors; fallback will handle */ },
          strict: "ignore",
        });
      } catch (_) {}
    }
    if (window.katex) {
      document.querySelectorAll('.math-katex').forEach(function(el){
        try { window.katex.render(el.textContent, el, { displayMode: (el.dataset.display === 'true') }); } catch (_) {}
      });
      // Fallback fix: rebuild math in common containers, avoiding code blocks
      document.querySelectorAll('.e-content.body p, .e-content.body li, .e-content.body h1, .e-content.body h2, .e-content.body h3, .e-content.body h4, .e-content.body blockquote, .e-content.body td, .e-content.body th, .e-content.body dd, .e-content.body dt, .e-content.body figcaption').forEach(function(el){
        if (safeContainer(el) && el.getAttribute('data-katex-rebuilt') !== '1') rebuildWithKatex(el);
      });
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
