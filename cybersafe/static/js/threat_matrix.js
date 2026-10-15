/**
 * CyberSafe Threat Matrix & Defensive Heatmap Visualizer
 * Renders interactive MITRE ATT&CK style technique mapping and control coverage indicators.
 */

class ThreatMatrixVisualizer {
    constructor(elementId) {
        this.container = document.getElementById(elementId);
        this.techniques = new Map();
        this.init();
    }

    init() {
        if (!this.container) return;
        this.setupGrid();
    }

    registerTechnique(id, name, coverageLevel, controlRefs = []) {
        this.techniques.set(id, {
            id,
            name,
            coverageLevel, // 'NONE', 'PARTIAL', 'ROBUST'
            controlRefs
        });
    }

    getCoverageColor(level) {
        switch (level) {
            case 'ROBUST': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
            case 'PARTIAL': return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
            default: return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
        }
    }

    setupGrid() {
        this.container.innerHTML = '';
        const grid = document.createElement('div');
        grid.className = 'grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3 p-4';
        for (const [id, tech] of this.techniques.entries()) {
            const card = document.createElement('div');
            card.className = `p-3 rounded border text-xs cursor-pointer transition hover:scale-105 ${this.getCoverageColor(tech.coverageLevel)}`;
            card.innerHTML = `
                <div class="font-mono text-[10px] opacity-75">${tech.id}</div>
                <div class="font-semibold truncate">${tech.name}</div>
                <div class="mt-1 text-[10px] opacity-90">${tech.coverageLevel}</div>
            `;
            grid.appendChild(card);
        }
        this.container.appendChild(grid);
    }
}

window.ThreatMatrixVisualizer = ThreatMatrixVisualizer;
