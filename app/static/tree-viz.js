(() => {
  const SVG_NS = "http://www.w3.org/2000/svg";

  const svgElement = (name, attributes = {}) => {
    const element = document.createElementNS(SVG_NS, name);
    Object.entries(attributes).forEach(([key, value]) => {
      element.setAttribute(key, String(value));
    });
    return element;
  };

  const shortHash = (value) => `${value.slice(0, 12)}…${value.slice(-8)}`;

  const startWaitingPoll = () => {
    const waiting = document.querySelector("[data-tree-waiting]");
    if (!waiting) return;
    const poll = async () => {
      try {
        const response = await fetch(waiting.dataset.treeStatusUrl);
        if (!response.ok) return;
        const tree = await response.json();
        if (tree.status === "ready" || tree.status === "failed") {
          window.location.reload();
        }
      } catch (_error) {
        // The summary remains available if polling temporarily fails.
      }
    };
    window.setInterval(poll, 1500);
  };

  class TreeVisualizer {
    constructor(root) {
      this.root = root;
      this.svg = root.querySelector("[data-viz-stage]");
      this.loading = root.querySelector("[data-viz-loading]");
      this.playButton = root.querySelector("[data-viz-play]");
      this.range = root.querySelector("[data-viz-range]");
      this.speed = root.querySelector("[data-viz-speed]");
      this.counter = root.querySelector("[data-viz-counter]");
      this.stepLabel = root.querySelector("[data-viz-step-label]");
      this.address = root.querySelector("[data-viz-address]");
      this.inspector = root.querySelector("[data-node-inspector]");
      this.currentStep = 0;
      this.timer = null;
      this.transform = { x: 0, y: 0, scale: 1 };
      this.drag = null;
      this.nodeElements = new Map();
      this.edgeElements = [];
    }

    async initialize() {
      try {
        const response = await fetch(this.root.dataset.visualizationUrl);
        if (!response.ok) throw new Error("Visualization artifact is unavailable");
        this.data = await response.json();
        this.range.max = this.data.insertion_events.length;
        this.buildGraph();
        this.bindControls();
        this.setStep(0);
        this.loading.hidden = true;
      } catch (error) {
        this.loading.textContent = error.message;
        this.loading.classList.add("error");
      }
    }

    buildGraph() {
      const nodeById = new Map(this.data.nodes.map((node) => [node.id, node]));
      const children = new Map(this.data.nodes.map((node) => [node.id, []]));
      this.data.edges.forEach((edge) => {
        const outgoing = children.get(edge.source);
        if (outgoing) outgoing.push(edge);
      });
      children.forEach((edges) => edges.sort((a, b) => a.label.localeCompare(b.label)));

      let leafCursor = 0;
      let maxStructuralDepth = 0;
      const assignPosition = (nodeId, structuralDepth = 0) => {
        const node = nodeById.get(nodeId);
        const outgoing = children.get(nodeId) || [];
        maxStructuralDepth = Math.max(maxStructuralDepth, structuralDepth);
        node.layoutDepth = structuralDepth;
        if (!outgoing.length) {
          node.layoutX = leafCursor++;
          return node.layoutX;
        }
        const childPositions = outgoing.map((edge) =>
          assignPosition(edge.target, structuralDepth + 1)
        );
        node.layoutX =
          childPositions.reduce((total, position) => total + position, 0) /
          childPositions.length;
        return node.layoutX;
      };
      assignPosition(this.data.root_id);

      const leafSpacing = 76;
      const levelSpacing = 125;
      const marginX = 70;
      const marginY = 65;
      const width = Math.max(900, Math.max(1, leafCursor - 1) * leafSpacing + 140);
      const height = Math.max(420, maxStructuralDepth * levelSpacing + 160);
      this.svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
      this.svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
      this.logicalSize = { width, height };

      nodeById.forEach((node) => {
        node.x =
          leafCursor <= 1
            ? width / 2
            : marginX +
              node.layoutX * ((width - marginX * 2) / (leafCursor - 1));
        node.y = marginY + node.layoutDepth * levelSpacing;
      });

      this.viewport = svgElement("g", { class: "tree-viewport" });
      const edgeLayer = svgElement("g", { class: "edge-layer" });
      const nodeLayer = svgElement("g", { class: "node-layer" });
      this.viewport.append(edgeLayer, nodeLayer);
      this.svg.replaceChildren(this.viewport);

      this.data.edges.forEach((edge) => {
        const source = nodeById.get(edge.source);
        const target = nodeById.get(edge.target);
        const group = svgElement("g", {
          class: "tree-edge",
          "data-reveal-step": edge.reveal_step,
        });
        const path = svgElement("path", {
          d: `M ${source.x} ${source.y + 16} C ${source.x} ${
            source.y + 58
          }, ${target.x} ${target.y - 58}, ${target.x} ${target.y - 16}`,
        });
        group.append(path);
        if (this.data.nodes.length <= 90) {
          const label = svgElement("text", {
            x: (source.x + target.x) / 2,
            y: (source.y + target.y) / 2 - 5,
          });
          label.textContent =
            edge.label.length > 6 ? `${edge.label.slice(0, 5)}…` : edge.label;
          group.append(label);
        }
        edgeLayer.append(group);
        this.edgeElements.push({ edge, element: group });
      });

      this.data.nodes.forEach((node) => {
        const group = svgElement("g", {
          class: `tree-node node-${node.type}`,
          transform: `translate(${node.x} ${node.y})`,
          tabindex: "0",
          role: "button",
          "aria-label": `${node.type} node ${node.hash_label}`,
          "data-node-id": node.id,
          "data-reveal-step": node.reveal_step,
        });
        if (node.type === "branch" || node.type === "internal") {
          group.append(svgElement("circle", { r: 16 }));
        } else if (node.type === "extension") {
          group.append(
            svgElement("rect", {
              x: -17,
              y: -13,
              width: 34,
              height: 26,
              rx: 7,
            })
          );
        } else {
          group.append(
            svgElement("path", { d: "M 0 -18 L 18 0 L 0 18 L -18 0 Z" })
          );
        }
        const typeLabel = svgElement("text", {
          class: "node-type-label",
          y: 4,
          "text-anchor": "middle",
        });
        typeLabel.textContent = {
          branch: "B",
          extension: "E",
          leaf: "L",
          internal: "I",
          suffix: "S",
        }[node.type];
        const hashLabel = svgElement("text", {
          class: "node-hash-label",
          y: 34,
          "text-anchor": "middle",
        });
        hashLabel.textContent = node.hash_label;
        group.append(typeLabel, hashLabel);
        group.addEventListener("click", (event) => {
          event.stopPropagation();
          this.inspectNode(node);
        });
        group.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") this.inspectNode(node);
        });
        nodeLayer.append(group);
        this.nodeElements.set(node.id, group);
      });
    }

    bindControls() {
      this.playButton.addEventListener("click", () => {
        if (this.timer) this.pause();
        else this.play();
      });
      this.range.addEventListener("input", () => {
        this.pause();
        this.setStep(Number(this.range.value));
      });
      this.root.querySelector("[data-viz-fit]").addEventListener("click", () => {
        this.transform = { x: 0, y: 0, scale: 1 };
        this.applyTransform();
      });

      this.svg.addEventListener(
        "wheel",
        (event) => {
          event.preventDefault();
          const nextScale = Math.min(
            6,
            Math.max(0.55, this.transform.scale * (event.deltaY < 0 ? 1.12 : 0.89))
          );
          this.transform.scale = nextScale;
          this.applyTransform();
        },
        { passive: false }
      );
      this.svg.addEventListener("pointerdown", (event) => {
        if (event.target.closest(".tree-node")) return;
        this.drag = {
          x: event.clientX,
          y: event.clientY,
          startX: this.transform.x,
          startY: this.transform.y,
        };
        this.svg.setPointerCapture(event.pointerId);
        this.svg.classList.add("is-panning");
      });
      this.svg.addEventListener("pointermove", (event) => {
        if (!this.drag) return;
        const rect = this.svg.getBoundingClientRect();
        this.transform.x =
          this.drag.startX +
          ((event.clientX - this.drag.x) * this.logicalSize.width) / rect.width;
        this.transform.y =
          this.drag.startY +
          ((event.clientY - this.drag.y) * this.logicalSize.height) / rect.height;
        this.applyTransform();
      });
      const stopDrag = () => {
        this.drag = null;
        this.svg.classList.remove("is-panning");
      };
      this.svg.addEventListener("pointerup", stopDrag);
      this.svg.addEventListener("pointercancel", stopDrag);
    }

    applyTransform() {
      this.viewport.setAttribute(
        "transform",
        `translate(${this.transform.x} ${this.transform.y}) scale(${this.transform.scale})`
      );
    }

    setStep(step) {
      const max = this.data.insertion_events.length;
      this.currentStep = Math.max(0, Math.min(max, step));
      this.range.value = this.currentStep;
      this.counter.textContent = `${this.currentStep} / ${max}`;
      const activeEvent =
        this.currentStep > 0
          ? this.data.insertion_events[this.currentStep - 1]
          : null;
      const activePath = new Set(activeEvent ? activeEvent.path : []);

      this.nodeElements.forEach((element, id) => {
        const revealStep = Number(element.dataset.revealStep);
        element.classList.toggle("is-revealed", revealStep < this.currentStep);
        element.classList.toggle("is-active-path", activePath.has(id));
      });
      this.edgeElements.forEach(({ edge, element }) => {
        const visible = edge.reveal_step < this.currentStep;
        const active =
          activePath.has(edge.source) && activePath.has(edge.target);
        element.classList.toggle("is-revealed", visible);
        element.classList.toggle("is-active-path", active);
      });

      if (activeEvent) {
        this.stepLabel.textContent = `Insertion ${activeEvent.number} · ${activeEvent.path.length} nodes · ${activeEvent.value_bytes} value bytes`;
        this.address.textContent = `${activeEvent.address} → ${shortHash(
          activeEvent.secure_trie_key
        )}`;
      } else {
        this.stepLabel.textContent = "Ready to replay";
        this.address.textContent = "No account selected";
      }
    }

    play() {
      if (this.currentStep >= this.data.insertion_events.length) this.setStep(0);
      this.playButton.innerHTML = "Ⅱ <span>Pause</span>";
      const advance = () => {
        if (this.currentStep >= this.data.insertion_events.length) {
          this.pause();
          return;
        }
        this.setStep(this.currentStep + 1);
        this.timer = window.setTimeout(advance, Number(this.speed.value));
      };
      advance();
    }

    pause() {
      if (this.timer) window.clearTimeout(this.timer);
      this.timer = null;
      this.playButton.innerHTML = "▶ <span>Play</span>";
    }

    inspectNode(node) {
      this.inspector.innerHTML = "";
      const eyebrow = document.createElement("p");
      eyebrow.className = "eyebrow";
      eyebrow.textContent = "Selected node";
      const heading = document.createElement("h3");
      heading.textContent = `${node.type[0].toUpperCase()}${node.type.slice(1)} node`;
      const list = document.createElement("dl");
      [
        ["Hash", node.hash],
        ["Reference", node.reference],
        ["Encoded size", `${node.rlp_bytes} bytes`],
        ["Encoding", node.encoding || "Ethereum RLP"],
        ["Structural depth", String(node.structural_depth)],
        ["Nibble depth", String(node.nibble_depth)],
        ["Path segment", node.path_segment || "—"],
        ["First visible", `Insertion ${node.reveal_step + 1}`],
      ].forEach(([label, value]) => {
        const row = document.createElement("div");
        const term = document.createElement("dt");
        const detail = document.createElement("dd");
        term.textContent = label;
        detail.textContent = value;
        row.append(term, detail);
        list.append(row);
      });
      this.inspector.append(eyebrow, heading, list);
      this.nodeElements.forEach((element, id) => {
        element.classList.toggle("is-selected", id === node.id);
      });
    }
  }

  startWaitingPoll();
  document.querySelectorAll("[data-tree-visualizer]").forEach((root) => {
    new TreeVisualizer(root).initialize();
  });
})();
