/*
 * Minimal vendored PrismJS-compatible Lua highlighter for the snulbug console.
 * It exposes Prism.highlight, Prism.highlightElement, and Prism.highlightAllUnder.
 */
(function () {
  "use strict";

  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));

  const tokenPatterns = [
    ["comment", /--\[\[[\s\S]*?\]\]|--[^\n]*/y],
    ["string", /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[(=*)\[[\s\S]*?\]\1\]/y],
    ["redacted", /\[REDACTED\]/y],
    ["number", /\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/y],
    ["keyword", /\b(?:and|break|do|else|elseif|end|for|function|goto|if|in|local|not|or|repeat|return|then|until|while)\b/y],
    ["boolean", /\b(?:false|true)\b/y],
    ["nil", /\bnil\b/y],
    ["function", /\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()/y],
    ["operator", /(?:\.\.\.?|==|~=|<=|>=|[+\-*/%#=<>])/y],
    ["punctuation", /[{}[\]();:,.]/y]
  ];

  function highlightLua(source) {
    let index = 0;
    let output = "";
    while (index < source.length) {
      let matched = false;
      for (const [name, pattern] of tokenPatterns) {
        pattern.lastIndex = index;
        const match = pattern.exec(source);
        if (match && match.index === index) {
          output += `<span class="token ${name}">${escapeHtml(match[0])}</span>`;
          index += match[0].length;
          matched = true;
          break;
        }
      }
      if (!matched) {
        output += escapeHtml(source[index]);
        index += 1;
      }
    }
    return output;
  }

  const Prism = {
    languages: { lua: {} },
    highlight(source, grammar, language) {
      if (language === "lua") return highlightLua(source);
      return escapeHtml(source);
    },
    highlightElement(element) {
      const language = Array.from(element.classList)
        .find((name) => name.startsWith("language-"))
        ?.slice("language-".length);
      element.innerHTML = Prism.highlight(element.textContent || "", Prism.languages[language], language);
    },
    highlightAllUnder(container) {
      container.querySelectorAll('code[class*="language-"]').forEach((element) => {
        Prism.highlightElement(element);
      });
    },
    highlightAll() {
      Prism.highlightAllUnder(document);
    }
  };

  window.Prism = Prism;
}());
