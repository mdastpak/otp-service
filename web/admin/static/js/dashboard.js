// OTP Service Admin Dashboard JavaScript
class AdminDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.settings = {
            refreshInterval: 5000,
            chartInterval: 10000,
            enableNotifications: true,
            enableSounds: true
        };
        
        this.init();
    }

    init() {
        this.loadSettings();
        this.initializeWebSocket();
        this.initializeCharts();
        this.bindEvents();
        this.startPeriodicUpdates();
        
        // Initialize UI
        this.updateConnectionStatus(false);
        this.loadInitialData();
    }

    // WebSocket Connection
    initializeWebSocket() {
        try {
            // Connect to WebSocket endpoint
            this.socket = io(window.location.origin, {
                path: '/admin/socket.io/',
                transports: ['websocket', 'polling']
            });

            this.socket.on('connect', () => {
                console.log('Connected to admin dashboard');
                this.updateConnectionStatus(true);
                this.socket.emit('admin_join');
            });

            this.socket.on('disconnect', () => {
                console.log('Disconnected from admin dashboard');
                this.updateConnectionStatus(false);
            });

            // Real-time data updates
            this.socket.on('stats_update', (data) => {
                this.updateStatistics(data);
            });

            this.socket.on('activity_update', (activity) => {
                this.addActivityItem(activity);
            });

            this.socket.on('health_update', (health) => {
                this.updateSystemHealth(health);
            });

            this.socket.on('chart_data', (chartData) => {
                this.updateCharts(chartData);
            });

        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.updateConnectionStatus(false);
        }
    }

    // Chart Initialization
    initializeCharts() {
        // Operations Timeline Chart
        const operationsCtx = document.getElementById('operationsChart').getContext('2d');
        this.charts.operations = new Chart(operationsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'OTP Generation',
                    data: [],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'OTP Verification',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: '#e2e8f0'
                        }
                    },
                    x: {
                        grid: {
                            color: '#e2e8f0'
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });

        // Success vs Failure Chart
        const successCtx = document.getElementById('successChart').getContext('2d');
        this.charts.success = new Chart(successCtx, {
            type: 'doughnut',
            data: {
                labels: ['Success', 'Failed', 'Rate Limited'],
                datasets: [{
                    data: [95, 3, 2],
                    backgroundColor: [
                        '#10b981',
                        '#ef4444',
                        '#f59e0b'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    }
                }
            }
        });
    }

    // Event Binding
    bindEvents() {
        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshDashboard();
        });

        // Settings modal
        const settingsBtn = document.getElementById('settingsBtn');
        const settingsModal = document.getElementById('settingsModal');
        const closeModal = document.getElementById('closeModal');
        const saveSettings = document.getElementById('saveSettings');
        const cancelSettings = document.getElementById('cancelSettings');

        settingsBtn.addEventListener('click', () => {
            this.showSettingsModal();
        });

        closeModal.addEventListener('click', () => {
            settingsModal.style.display = 'none';
        });

        cancelSettings.addEventListener('click', () => {
            settingsModal.style.display = 'none';
        });

        saveSettings.addEventListener('click', () => {
            this.saveSettings();
            settingsModal.style.display = 'none';
        });

        // Activity filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.setActiveFilter(e.target);
                this.filterActivities(e.target.dataset.filter);
            });
        });

        // Close modal on outside click
        window.addEventListener('click', (e) => {
            if (e.target === settingsModal) {
                settingsModal.style.display = 'none';
            }
        });
    }

    // Data Loading and Updates
    async loadInitialData() {
        try {
            const response = await fetch('/admin/api/dashboard-data');
            const data = await response.json();
            
            this.updateStatistics(data.stats);
            this.updateSystemHealth(data.health);
            this.loadRecentActivities(data.activities);
            this.updateCharts(data.chartData);
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
        }
    }

    updateStatistics(stats) {
        if (!stats) return;

        // Update stat values
        this.updateElement('activeOtps', stats.activeOtps?.toLocaleString() || '0');
        this.updateElement('successRate', `${(stats.successRate || 0).toFixed(1)}%`);
        this.updateElement('avgResponseTime', `${stats.avgResponseTime || 0}ms`);
        this.updateElement('rateLimited', stats.rateLimited?.toLocaleString() || '0');

        // Update trends
        this.updateTrend('activeOtpTrend', stats.trends?.activeOtps);
        this.updateTrend('successRateTrend', stats.trends?.successRate);
        this.updateTrend('responseTimeTrend', stats.trends?.responseTime);
        this.updateTrend('rateLimitTrend', stats.trends?.rateLimited);
    }

    updateSystemHealth(health) {
        if (!health) return;

        const healthItems = ['api', 'redis', 'memory', 'cpu'];
        
        healthItems.forEach(item => {
            const indicator = document.getElementById(`${item}HealthIndicator`);
            const status = document.getElementById(`${item}HealthStatus`);
            
            if (health[item] && indicator && status) {
                indicator.className = `health-indicator ${health[item].status}`;
                status.textContent = health[item].statusText;
                
                const uptimeEl = document.getElementById(`${item}Uptime`);
                if (uptimeEl && health[item].details) {
                    uptimeEl.textContent = health[item].details;
                }
            }
        });
    }

    addActivityItem(activity) {
        const feed = document.getElementById('activityFeed');
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.dataset.type = activity.type;
        
        const iconClass = this.getActivityIconClass(activity.type);
        const timeAgo = this.timeAgo(new Date(activity.timestamp));
        
        item.innerHTML = `
            <div class="activity-icon ${iconClass}">
                ${this.getActivityIcon(activity.type)}
            </div>
            <div class="activity-details">
                <div class="activity-message">${activity.message}</div>
                <div class="activity-time">${timeAgo}</div>
            </div>
        `;
        
        feed.insertBefore(item, feed.firstChild);
        
        // Keep only last 100 items
        while (feed.children.length > 100) {
            feed.removeChild(feed.lastChild);
        }
        
        // Show notification if enabled
        if (this.settings.enableNotifications && activity.type === 'failure') {
            this.showNotification('System Alert', activity.message, 'error');
        }
    }

    loadRecentActivities(activities) {
        const feed = document.getElementById('activityFeed');
        feed.innerHTML = '';
        
        activities.forEach(activity => {
            this.addActivityItem(activity);
        });
    }

    updateCharts(chartData) {
        if (!chartData) return;

        // Update operations chart
        if (chartData.operations && this.charts.operations) {
            this.charts.operations.data.labels = chartData.operations.labels;
            this.charts.operations.data.datasets[0].data = chartData.operations.generation;
            this.charts.operations.data.datasets[1].data = chartData.operations.verification;
            this.charts.operations.update('none');
        }

        // Update success chart
        if (chartData.success && this.charts.success) {
            this.charts.success.data.datasets[0].data = [
                chartData.success.successful,
                chartData.success.failed,
                chartData.success.rateLimited
            ];
            this.charts.success.update('none');
        }
    }

    // UI Helper Methods
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    updateTrend(id, trend) {
        const element = document.getElementById(id);
        if (!element || !trend) return;

        element.textContent = trend.value;
        element.className = `stat-trend ${trend.direction}`;
    }

    updateConnectionStatus(connected) {
        const statusEl = document.getElementById('connectionStatus');
        if (connected) {
            statusEl.textContent = '🟢 Connected';
            statusEl.className = 'connection-status connected';
        } else {
            statusEl.textContent = '🔴 Disconnected';
            statusEl.className = 'connection-status';
        }
    }

    setActiveFilter(button) {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        button.classList.add('active');
    }

    filterActivities(filter) {
        const items = document.querySelectorAll('.activity-item');
        items.forEach(item => {
            if (filter === 'all' || item.dataset.type === filter) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }

    getActivityIconClass(type) {
        switch (type) {
            case 'success': return 'success';
            case 'failure': return 'failure';
            case 'rate-limit': return 'rate-limit';
            default: return 'success';
        }
    }

    getActivityIcon(type) {
        switch (type) {
            case 'success': return '✓';
            case 'failure': return '✗';
            case 'rate-limit': return '⚠';
            default: return '•';
        }
    }

    timeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        
        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + ' years ago';
        
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + ' months ago';
        
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + ' days ago';
        
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + ' hours ago';
        
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + ' minutes ago';
        
        return Math.floor(seconds) + ' seconds ago';
    }

    // Settings Management
    showSettingsModal() {
        const modal = document.getElementById('settingsModal');
        modal.style.display = 'block';
        
        // Load current settings into form
        document.getElementById('refreshInterval').value = this.settings.refreshInterval / 1000;
        document.getElementById('chartInterval').value = this.settings.chartInterval / 1000;
        document.getElementById('enableNotifications').checked = this.settings.enableNotifications;
        document.getElementById('enableSounds').checked = this.settings.enableSounds;
    }

    saveSettings() {
        this.settings.refreshInterval = parseInt(document.getElementById('refreshInterval').value) * 1000;
        this.settings.chartInterval = parseInt(document.getElementById('chartInterval').value) * 1000;
        this.settings.enableNotifications = document.getElementById('enableNotifications').checked;
        this.settings.enableSounds = document.getElementById('enableSounds').checked;
        
        localStorage.setItem('dashboardSettings', JSON.stringify(this.settings));
        
        // Restart periodic updates with new intervals
        this.startPeriodicUpdates();
        
        this.showNotification('Settings Saved', 'Dashboard settings have been updated successfully.', 'success');
    }

    loadSettings() {
        const saved = localStorage.getItem('dashboardSettings');
        if (saved) {
            this.settings = { ...this.settings, ...JSON.parse(saved) };
        }
    }

    // Periodic Updates
    startPeriodicUpdates() {
        // Clear existing intervals
        if (this.refreshTimer) clearInterval(this.refreshTimer);
        if (this.chartTimer) clearInterval(this.chartTimer);
        
        // Start new intervals
        this.refreshTimer = setInterval(() => {
            this.loadInitialData();
        }, this.settings.refreshInterval);
        
        this.chartTimer = setInterval(() => {
            this.requestChartUpdate();
        }, this.settings.chartInterval);
    }

    refreshDashboard() {
        this.loadInitialData();
        this.showNotification('Dashboard Refreshed', 'All data has been updated.', 'success');
    }

    requestChartUpdate() {
        if (this.socket && this.socket.connected) {
            this.socket.emit('request_chart_update');
        }
    }

    // Notifications
    showNotification(title, message, type = 'info') {
        if (!this.settings.enableNotifications) return;

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <strong>${title}</strong><br>
            ${message}
        `;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
        
        // Play sound if enabled
        if (this.settings.enableSounds && type === 'error') {
            this.playAlertSound();
        }
    }

    playAlertSound() {
        // Create a simple beep sound
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
        gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.2);
    }

    // Cleanup
    destroy() {
        if (this.socket) {
            this.socket.disconnect();
        }
        
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
        
        if (this.chartTimer) {
            clearInterval(this.chartTimer);
        }
        
        Object.values(this.charts).forEach(chart => {
            if (chart && chart.destroy) {
                chart.destroy();
            }
        });
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new AdminDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.dashboard) {
        window.dashboard.destroy();
    }
});