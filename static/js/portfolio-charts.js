/**
 * @fileoverview Portfolio visualization and management module
 * This module handles the visualization and interaction with portfolio data
 * using Chart.js library. It implements secure data handling practices and
 * follows modern JavaScript patterns.
 * 
 * @requires chart.js
 * @module PortfolioCharts
 */

import { formatCurrency } from "./utils.js";

// IIFE to avoid polluting global namespace
const PortfolioCharts = (function () {
    'use strict';

    // Private state
    const state = {
        chart: null,
        config: {
            colors: {
                positive: {
                    background: 'rgba(40, 167, 69, 0.5)',
                    border: 'rgb(40, 167, 69)'
                },
                negative: {
                    background: 'rgba(220, 53, 69, 0.5)',
                    border: 'rgb(220, 53, 69)'
                }
            },
            chartStyles: [
                'rgba(255, 99, 132, 0.5)',
                'rgba(54, 162, 235, 0.5)',
                'rgba(255, 206, 86, 0.5)',
                'rgba(75, 192, 192, 0.5)',
                'rgba(153, 102, 255, 0.5)'
            ]
        }
    };

    /**
     * Sanitizes string input to prevent XSS attacks
     * @param {string} str - Input string to sanitize
     * @returns {string} Sanitized string
     * @private
     */
    const sanitizeHTML = (str) => {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    };

    /**
     * Safely parses numeric values
     * @param {string} value - Value to parse
     * @returns {number} Parsed number or 0 if invalid
     * @private
     */
    const safeParseFloat = (value) => {
        const parsed = parseFloat(value.replace(/[^0-9.-]+/g, ''));
        return isFinite(parsed) ? parsed : 0;
    };

    /**
     * Creates chart container with secure HTML
     * @returns {HTMLElement} Chart container element
     * @private
     */
    const createChartContainer = () => {
        const container = document.createElement('div');
        container.className = 'card mb-4';
        container.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">${sanitizeHTML('Portfolio Distribution')}</h5>
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-secondary" id="pieView">Distribution</button>
                    <button class="btn btn-sm btn-outline-secondary active" id="barView">Holdings</button>
                </div>
            </div>
            <div class="card-body">
                <canvas id="portfolioChart" style="height: 300px;"></canvas>
            </div>
        `;
        return container;
    };

    /**
     * Extracts and validates portfolio data from DOM
     * @returns {Array<Object>} Validated portfolio data
     * @private
     */
    const extractPortfolioData = () => {
        const rows = document.querySelectorAll('#portfolioTable tbody tr');
        return Array.from(rows).map(row => {
            const profitLossText = row.querySelector('.profit-loss')?.textContent || '0';
            return {
                name: sanitizeHTML(row.querySelector('.crypto-name')?.textContent?.trim() || ''),
                amount: safeParseFloat(row.querySelector('td:nth-child(2) .display-value')?.textContent || '0'),
                currentValue: safeParseFloat(row.querySelector('.current-value')?.textContent || '0'),
                profitLoss: safeParseFloat(profitLossText.split('(')[0] || '0')
            };
        });
    };

    /**
     * Creates secure bar chart configuration
     * @param {Array<Object>} data - Portfolio data
     * @returns {Object} Chart.js configuration object
     * @private
     */
    const createBarChartConfig = (data) => {
        const currency = document.getElementById('currencySelect')?.value || 'USD';
        const maxAbsValue = Math.max(...data.map(item => Math.abs(item.profitLoss)));

        return {
            type: 'bar',
            data: {
                labels: data.map(item => sanitizeHTML(item.name)),
                datasets: [{
                    label: 'Profit/Loss',
                    data: data.map(item => item.profitLoss),
                    backgroundColor: data.map(item =>
                        item.profitLoss >= 0 ? state.config.colors.positive.background : state.config.colors.negative.background
                    ),
                    borderColor: data.map(item =>
                        item.profitLoss >= 0 ? state.config.colors.positive.border : state.config.colors.negative.border
                    ),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        suggestedMin: -maxAbsValue,
                        suggestedMax: maxAbsValue,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)',
                            zeroLineColor: 'rgba(0, 0, 0, 0.25)',
                            zeroLineWidth: 2
                        },
                        ticks: {
                            callback: (value) => formatCurrency(value, currency)
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const value = context.raw;
                                const formattedValue = formatCurrency(value, currency);
                                const percentageChange = ((value / data[context.dataIndex].currentValue) * 100).toFixed(2);
                                return `${formattedValue} (${percentageChange}%)`;
                            }
                        }
                    },
                    legend: {
                        display: false
                    }
                }
            }
        };
    };

    /**
     * Creates secure pie chart configuration
     * @param {Array<Object>} data - Portfolio data
     * @returns {Object} Chart.js configuration object
     * @private
     */
    const createPieChartConfig = (data) => {
        const currency = document.getElementById('currencySelect')?.value || 'USD';

        return {
            type: 'pie',
            data: {
                labels: data.map(item => sanitizeHTML(item.name)),
                datasets: [{
                    data: data.map(item => Math.abs(item.currentValue)),
                    backgroundColor: state.config.chartStyles,
                    borderColor: state.config.chartStyles.map(color => color.replace('0.5', '1'))
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const value = context.raw;
                                const formattedValue = formatCurrency(value, currency);
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${sanitizeHTML(context.label)}: ${formattedValue} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        };
    };

    /**
     * Table sorting functionality
     * @private
     */
    const TableSorter = {
        sortTypes: {
            0: 'text',
            1: 'number',
            2: 'number',
            3: 'date',
            4: 'number',
            5: 'number',
            6: 'number'
        },

        getCellValue(row, columnIndex, sortType) {
            const cell = row.cells[columnIndex];
            const displayValue = cell.querySelector('.display-value');
            const value = displayValue ? displayValue.textContent : cell.textContent;

            switch (sortType) {
                case 'number': return safeParseFloat(value);
                case 'date': return new Date(value);
                default: return value.trim().toLowerCase();
            }
        },

        sortTable(columnIndex, header) {
            const table = document.getElementById('portfolioTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));

            // Reset other headers
            table.querySelectorAll('th').forEach(th => {
                if (th !== header) {
                    th.dataset.sortDirection = 'none';
                    this.updateSortIndicator(th, 'none');
                }
            });

            const currentDirection = header.dataset.sortDirection;
            const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
            header.dataset.sortDirection = newDirection;
            this.updateSortIndicator(header, newDirection);

            const sortType = this.sortTypes[columnIndex];
            rows.sort((rowA, rowB) => {
                const valueA = this.getCellValue(rowA, columnIndex, sortType);
                const valueB = this.getCellValue(rowB, columnIndex, sortType);

                if (!valueA && valueA !== 0) return 1;
                if (!valueB && valueB !== 0) return -1;

                return newDirection === 'asc' ?
                    (valueA < valueB ? -1 : valueA > valueB ? 1 : 0) :
                    (valueA > valueB ? -1 : valueA < valueB ? 1 : 0);
            });

            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        }
    };

    /**
     * Public methods
     */
    return {
        /**
         * Initializes the portfolio visualization
         * @public
         */
        initialize() {
            try {
                const portfolioTable = document.querySelector('#portfolioTable');
                if (!portfolioTable) {
                    throw new Error('Portfolio table not found');
                }

                const container = createChartContainer();
                portfolioTable.parentNode.insertBefore(container, portfolioTable);

                const portfolioData = extractPortfolioData();
                const ctx = document.getElementById('portfolioChart')?.getContext('2d');
                if (!ctx) {
                    throw new Error('Canvas context not available');
                }

                state.chart = new Chart(ctx, createBarChartConfig(portfolioData));

                // Event listeners using event delegation
                document.addEventListener('click', (e) => {
                    if (e.target.id === 'pieView') {
                        this.switchChartType('pie', portfolioData);
                        this.toggleActiveButton('pieView');
                    } else if (e.target.id === 'barView') {
                        this.switchChartType('bar', portfolioData);
                        this.toggleActiveButton('barView');
                    }
                });

                this.initializeTableSorting();
            } catch (error) {
                console.error('Portfolio chart initialization failed:', error);
                this.handleError(error);
            }
        },

        /**
         * Switches between chart types
         * @param {string} type - Chart type ('pie' or 'bar')
         * @param {Array<Object>} data - Portfolio data
         * @public
         */
        switchChartType(type, data) {
            try {
                const ctx = document.getElementById('portfolioChart')?.getContext('2d');
                if (!ctx) {
                    throw new Error('Canvas context not available');
                }

                if (state.chart) {
                    state.chart.destroy();
                }

                const config = type === 'pie' ? createPieChartConfig(data) : createBarChartConfig(data);
                state.chart = new Chart(ctx, config);
            } catch (error) {
                console.error('Chart type switch failed:', error);
                this.handleError(error);
            }
        },

        /**
         * Initializes table sorting functionality
         * @public
         */
        initializeTableSorting() {
            const table = document.getElementById('portfolioTable');
            const thead = table.querySelector('thead');

            thead.querySelectorAll('th').forEach((th, index) => {
                if (index < thead.querySelectorAll('th').length - 1) {
                    th.style.cursor = 'pointer';
                    th.dataset.sortDirection = 'none';
                    th.dataset.sortType = TableSorter.sortTypes[index];

                    const indicator = document.createElement('span');
                    indicator.className = 'sort-indicator';
                    indicator.textContent = '⇅';
                    th.appendChild(indicator);

                    th.addEventListener('click', () => TableSorter.sortTable.call(TableSorter, index, th));
                }
            });
        },

        /**
         * Handles errors gracefully
         * @param {Error} error - Error object
         * @private
         */
        handleError(error) {
            const chartContainer = document.querySelector('#portfolioChart')?.closest('.card');
            if (chartContainer) {
                chartContainer.innerHTML = `
                    <div class="alert alert-warning m-3">
                        ${sanitizeHTML('Unable to load portfolio visualization. Please try refreshing the page.')}
                    </div>
                `;
            }
        },

        /**
         * Toggles active state of chart view buttons
         * @param {string} activeId - ID of active button
         * @private
         */
        toggleActiveButton(activeId) {
            document.querySelectorAll('.btn-group .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById(activeId)?.classList.add('active');
        }
    };
})();

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', () => {
    const chartScript = document.createElement('script');
    chartScript.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    chartScript.integrity = 'sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC';
    chartScript.crossOrigin = 'anonymous';

    // Add styles
    const styles = `
        .sort-indicator {
            font-size: 0.8em;
            margin-left: 5px;
            color: #6c757d;
        }
        
        .btn-group .btn.active {
            background-color: #6c757d;
            color: white;
            border-color: #6c757d;
        }
        
        .btn-group .btn:focus {
            box-shadow: none;
            outline: 2px solid rgba(108, 117, 125, 0.5);
        }
    `;

    const styleSheet = document.createElement('style');
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);

    // Initialize portfolio charts after Chart.js loads
    chartScript.onload = () => {
        try {
            PortfolioCharts.initialize();
        } catch (error) {
            console.error('Failed to initialize portfolio features:', error);
            PortfolioCharts.handleError(error);
        }
    };

    chartScript.onerror = (error) => {
        console.error('Failed to load Chart.js:', error);
        PortfolioCharts.handleError(new Error('Failed to load required dependencies'));
    };

    document.head.appendChild(chartScript);
});

// Export for module usage
export default PortfolioCharts;