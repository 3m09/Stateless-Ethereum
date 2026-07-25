(() => {
  const targets = document.querySelectorAll("[data-poll-url]");

  targets.forEach((target) => {
    const interval = Number(target.dataset.pollInterval || 5000);
    const url = target.dataset.pollUrl;

    const refresh = async () => {
      if (document.hidden) return;
      try {
        const response = await fetch(url, {
          headers: { "X-Requested-With": "fetch" },
        });
        if (response.ok) {
          target.innerHTML = await response.text();
        }
      } catch (_error) {
        // The current content remains visible if a refresh fails.
      }
    };

    window.setInterval(refresh, interval);
  });

  document.querySelectorAll("[data-tree-config-form]").forEach((form) => {
    const treeType = form.querySelector("[data-tree-type]");
    const hash = form.querySelector("[data-tree-hash]");
    const setup = form.querySelector("[data-tree-setup]");
    const width = form.querySelector("[data-tree-width]");
    const widthHelp = form.querySelector("[data-tree-width-help]");
    if (!treeType || !hash || !setup || !width) return;

    const applyTreeProfile = (resetWidth = false) => {
      if (treeType.value === "merkle_patricia") {
        hash.value = "keccak";
        setup.value = "";
        width.min = "4";
        width.max = "128";
        width.step = "1";
        if (resetWidth || Number(width.value) > 128) width.value = "16";
        if (widthHelp) {
          widthHelp.textContent =
            "Radix width 4–128; width 16 is the Ethereum-compatible MPT.";
        }
      } else if (treeType.value === "poseidon_merkle") {
        hash.value = "poseidon";
        setup.value = "";
        width.min = "4";
        width.max = "128";
        width.step = "1";
        if (resetWidth || Number(width.value) > 128) width.value = "16";
        if (widthHelp) {
          widthHelp.textContent =
            "Radix width 4–128; width 16 retains the fixed zkSNARK layout.";
        }
      } else {
        hash.value = "kzg";
        setup.value = "verkle_kzg";
        width.min = "16";
        width.max = "512";
        width.step = "16";
        if (resetWidth) width.value = "256";
        if (widthHelp) {
          widthHelp.textContent =
            "KZG Verkle accepts 16, 32, 64, 128, 256, or 512.";
        }
      }
    };

    treeType.addEventListener("change", () => applyTreeProfile(true));
    applyTreeProfile(false);
  });
})();
