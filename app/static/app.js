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
          if (
            target.dataset.reloadTerminal === "true" &&
            target.querySelector("[data-terminal='true']")
          ) {
            window.location.reload();
          }
        }
      } catch (_error) {
        // The current content remains visible if a refresh fails.
      }
    };

    window.setInterval(refresh, interval);
  });

  document.querySelectorAll("[data-proof-form]").forEach((form) => {
    const tree = form.querySelector("[data-proof-tree]");
    const profile = form.querySelector("[data-proof-profile]");
    const prover = form.querySelector("[data-proof-prover]");
    const verifier = form.querySelector("[data-proof-verifier]");
    const setup = form.querySelector("[data-proof-setup]");
    const proverLabel = form.querySelector("[data-proof-prover-label]");
    const verifierLabel = form.querySelector("[data-proof-verifier-label]");
    const setupLabel = form.querySelector("[data-proof-setup-label]");
    const keyCount = form.querySelector("[data-proof-key-count]");
    const keyHelp = form.querySelector("[data-proof-key-help]");
    const submit = form.querySelector("button[type='submit']");
    if (!tree || !profile) return;

    const applyProfile = () => {
      const option = profile.selectedOptions[0];
      if (!option) return;
      prover.value = option.dataset.prover;
      verifier.value = option.dataset.verifier;
      setup.value = option.dataset.setup;
      proverLabel.textContent = prover.value;
      verifierLabel.textContent = verifier.value;
      setupLabel.textContent = setup.value || "none";
    };

    const filterProfiles = () => {
      const treeOption = tree.selectedOptions[0];
      if (!treeOption) return;
      let firstCompatible = null;
      Array.from(profile.options).forEach((option) => {
        const compatible =
          option.dataset.treeType === treeOption.dataset.treeType &&
          option.dataset.hashFunction === treeOption.dataset.hashFunction;
        option.hidden = !compatible;
        option.disabled = !compatible;
        if (compatible && !firstCompatible) firstCompatible = option;
      });
      if (!profile.selectedOptions[0] || profile.selectedOptions[0].disabled) {
        if (firstCompatible) profile.value = firstCompatible.value;
      }
      profile.disabled = !firstCompatible;
      if (submit) submit.disabled = !firstCompatible;
      const maximum = Number(treeOption.dataset.keyCount || 1);
      keyCount.max = String(maximum);
      if (Number(keyCount.value) > maximum) keyCount.value = String(maximum);
      keyHelp.textContent = `The selected tree contains ${maximum} keys.`;
      if (!firstCompatible) {
        keyHelp.textContent =
          "This tree does not yet have a complete runnable proof contract.";
      }
      applyProfile();
    };

    tree.addEventListener("change", filterProfiles);
    profile.addEventListener("change", applyProfile);
    filterProfiles();
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
