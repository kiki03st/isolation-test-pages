(function () {
  'use strict';
  var GROUPS = {
    collection: '수집', navigation: '이동', analysis: '분석', network: '네트워크',
    session: '세션', download: '다운로드', http: 'HTTP 응답', limits: '한도',
    host: '호스트', integration: '연동', recovery: '복구'
  };
  var root = new URL('.', document.baseURI);
  var items = [];
  var search = document.getElementById('search');
  var category = document.getElementById('category');
  var statusBox = document.getElementById('status');
  var fallback = document.getElementById('fallback');
  var fallbackText = document.getElementById('fallback-text');
  var list = document.getElementById('cases');
  var httpBase = null;

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined) { node.textContent = text; }
    if (className) { node.className = className; }
    return node;
  }

  function variantUrl(item, variant) {
    if (variant.path) { return new URL(variant.path, root).href; }
    if (item.execution_kind === 'http_fixture' && httpBase && item.relative_path) {
      return httpBase + item.relative_path + '/' + variant.name;
    }
    return null;
  }

  function showFallback(text) {
    fallback.hidden = false;
    fallbackText.value = text;
    fallbackText.focus();
    fallbackText.select();
    statusBox.textContent = '자동 복사를 사용할 수 없어 선택된 텍스트를 표시했습니다.';
  }

  function copy(text) {
    var clipboard = navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== 'function') { showFallback(text); return; }
    var attempt;
    try { attempt = clipboard.writeText(text); } catch (error) { showFallback(text); return; }
    Promise.resolve(attempt).then(function () {
      fallback.hidden = true;
      statusBox.textContent = '복사했습니다.';
    }, function () { showFallback(text); });
  }

  function button(label, text, enabled) {
    var node = el('button', label);
    node.type = 'button';
    node.disabled = !enabled;
    if (enabled) { node.addEventListener('click', function () { copy(text); }); }
    return node;
  }

  function render(item) {
    var card = el('article', undefined, 'case');
    var title = el('h2');
    title.appendChild(el('span', item.id, 'case-id'));
    title.appendChild(el('span', item.title));
    card.appendChild(title);
    card.appendChild(el('p', item.description));
    if (item.message) {
      card.appendChild(el('p', item.message, 'message'));
      card.appendChild(button('문자 복사', item.message, true));
    }
    var variants = el('ul', undefined, 'variants');
    item.variants.forEach(function (variant) {
      var row = el('li');
      var url = variantUrl(item, variant);
      row.appendChild(el('code', variant.name));
      if (url) {
        var link = el('a', '열기');
        link.href = url;
        row.appendChild(link);
      } else {
        row.appendChild(el('span', '사용 불가: 준비되지 않음', 'unavailable'));
      }
      row.appendChild(button('URL 복사', url, Boolean(url)));
      variants.appendChild(row);
    });
    card.appendChild(variants);
    return card;
  }

  function apply() {
    var query = search.value.trim().toLowerCase();
    var group = category.value;
    items.forEach(function (entry) {
      var haystack = [entry.item.id, entry.item.title, entry.item.message, entry.item.description]
        .join('\n').toLowerCase();
      entry.node.hidden = !((!group || entry.item.group === group) &&
        (!query || haystack.indexOf(query) !== -1));
    });
  }

  fetch(new URL('catalog.json', root), { cache: 'no-store' }).then(function (response) {
    if (!response.ok) { throw new Error('catalog'); }
    return response.json();
  }).then(function (catalog) {
    if (typeof catalog.http_base === 'string' && /^https:\/\//.test(catalog.http_base)) {
      httpBase = catalog.http_base;
    }
    var groups = {};
    catalog.cases.forEach(function (item) {
      groups[item.group] = true;
      var node = render(item);
      items.push({ item: item, node: node });
      list.appendChild(node);
    });
    Object.keys(groups).forEach(function (name) {
      var option = el('option', GROUPS[name] || name);
      option.value = name;
      category.appendChild(option);
    });
    document.getElementById('source').textContent = '기준 커밋: ' + String(catalog.commit_sha).slice(0, 12);
  }).catch(function () {
    statusBox.textContent = '목록을 불러오지 못했습니다.';
  });

  search.addEventListener('input', apply);
  category.addEventListener('change', apply);
}());
