/**
 * CyberSafe Midnight & Cyan Chart.js Presets
 */

const CyberChartThemes = {
    navyDark: '#081220',
    gridColor: 'rgba(24, 46, 75, 0.45)',
    textColor: '#8da4be',
    cyanAccent: '#00f0ff',
    oceanBlue: '#0066cc',
    emerald: '#10b981',
    amber: '#f59e0b',
    rose: '#f43f5e',

    // Radar Chart for Categories
    initRadarChart(canvasId, labels, dataPoints) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        return new Chart(ctx, {
            type: 'radar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Compliance Level (%)',
                    data: dataPoints,
                    backgroundColor: 'rgba(0, 102, 204, 0.25)',
                    borderColor: '#00f0ff',
                    pointBackgroundColor: '#00f0ff',
                    pointBorderColor: '#ffffff',
                    pointHoverBackgroundColor: '#ffffff',
                    pointHoverBorderColor: '#00f0ff',
                    borderWidth: 2,
                    pointRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: { color: this.gridColor },
                        grid: { color: this.gridColor },
                        pointLabels: {
                            color: '#f8fafc',
                            font: { size: 11, weight: '600', family: 'Inter' }
                        },
                        ticks: {
                            backdropColor: 'transparent',
                            color: this.textColor,
                            stepSize: 20,
                            beginAtZero: true,
                            max: 100
                        }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    },

    // Doughnut Score Gauge
    initScoreGauge(canvasId, score) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        const remaining = Math.max(0, 100 - score);
        let scoreColor = this.emerald;
        if (score < 60) scoreColor = this.rose;
        else if (score < 85) scoreColor = this.amber;

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Compliant', 'Gap'],
                datasets: [{
                    data: [score, remaining],
                    backgroundColor: [scoreColor, 'rgba(24, 46, 75, 0.6)'],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '78%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    },

    // Category Bar Chart
    initCategoryBarChart(canvasId, labels, values) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Category Compliance %',
                    data: values,
                    backgroundColor: values.map(v => v >= 85 ? 'rgba(16, 185, 129, 0.7)' : (v >= 60 ? 'rgba(0, 102, 204, 0.7)' : 'rgba(244, 63, 94, 0.7)')),
                    borderColor: values.map(v => v >= 85 ? '#10b981' : (v >= 60 ? '#00f0ff' : '#f43f5e')),
                    borderWidth: 1,
                    borderRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: this.gridColor },
                        ticks: { color: this.textColor, callback: v => v + '%' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: this.textColor, font: { size: 10 } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
};
