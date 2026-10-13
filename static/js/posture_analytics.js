/**
 * CyberSafe Posture Analytics & Visualizations Engine
 * Provides client-side compliance calculations, radar chart rendering, and trend forecasting.
 */

class PostureAnalyticsEngine {
    constructor(config = {}) {
        this.config = Object.assign({
            refreshIntervalMs: 30000,
            primaryColor: '#00f0ff',
            secondaryColor: '#0066cc',
            dangerColor: '#ef4444',
            warningColor: '#f59e0b',
            successColor: '#10b981',
            canvasId: 'postureRadarChart'
        }, config);
        this.history = [];
        this.metrics = new Map();
        this.init();
    }

    init() {
        this.bindEvents();
        this.renderCategoryBreakdown();
    }

    bindEvents() {
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.refreshMetrics();
            }
        });
    }

    registerCategoryScore(categoryName, compliantWeight, totalWeight) {
        if (!totalWeight || totalWeight <= 0) return 0;
        const score = Math.min(100, Math.max(0, (compliantWeight / totalWeight) * 100));
        this.metrics.set(categoryName, {
            score: Math.round(score * 10) / 10,
            compliantWeight,
            totalWeight,
            timestamp: Date.now()
        });
        return score;
    }

    calculateOverallPostureIndex() {
        if (this.metrics.size === 0) return 0;
        let sumScore = 0;
        for (const [_, data] of this.metrics.entries()) {
            sumScore += data.score;
        }
        return Math.round((sumScore / this.metrics.size) * 10) / 10;
    }

    getRiskTier(score) {
        if (score >= 85) return { tier: 'Low Risk', badgeClass: 'bg-emerald-500/20 text-emerald-400' };
        if (score >= 65) return { tier: 'Moderate Risk', badgeClass: 'bg-amber-500/20 text-amber-400' };
        return { tier: 'High Risk', badgeClass: 'bg-rose-500/20 text-rose-400' };
    }

    renderCategoryBreakdown() {
        const container = document.getElementById('categoryBreakdownContainer');
        if (!container) return;
        container.innerHTML = '';
        for (const [catName, data] of this.metrics.entries()) {
            const bar = document.createElement('div');
            bar.className = 'mb-3';
            bar.innerHTML = `
                <div class="flex justify-between text-xs text-slate-300 mb-1">
                    <span>${catName}</span>
                    <span class="font-mono text-cyan-400">${data.score}%</span>
                </div>
                <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div class="bg-cyan-500 h-2 rounded-full transition-all duration-500" style="width: ${data.score}%"></div>
                </div>
            `;
            container.appendChild(bar);
        }
    }

    exportPostureReport() {
        const report = {
            generatedAt: new Date().toISOString(),
            overallScore: this.calculateOverallPostureIndex(),
            categories: Object.fromEntries(this.metrics)
        };
        return JSON.stringify(report, null, 2);
    }
}

window.PostureAnalyticsEngine = PostureAnalyticsEngine;
