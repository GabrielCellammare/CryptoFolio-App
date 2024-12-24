// portfolio-charts.js
import { formatCurrency } from "./utils.js";
/**
 * Initializes the portfolio chart with current portfolio data
 * Uses the portfolio data already available in the DOM to avoid additional API calls
 */
// Store the chart instance globally so we can access it for cleanup
let currentChart = null;

/**
 * Initializes the portfolio chart with current portfolio data
 */

function initializePortfolioChart() {
    const chartContainer = document.createElement('div');
    chartContainer.className = 'card mb-4';
    chartContainer.innerHTML = `
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">Portfolio Distribution</h5>
            <div class="btn-group">
                <button class="btn btn-sm btn-outline-secondary" id="pieView">Distribution</button>
                <button class="btn btn-sm btn-outline-secondary active" id="barView">Holdings</button>
            </div>
        </div>
        <div class="card-body">
            <canvas id="portfolioChart" style="height: 300px;"></canvas>
        </div>
    `;

    const portfolioTable = document.querySelector('#portfolioTable');
    portfolioTable.parentNode.insertBefore(chartContainer, portfolioTable);

    const portfolioData = extractPortfolioData();
    const ctx = document.getElementById('portfolioChart').getContext('2d');
    currentChart = new Chart(ctx, createBarChartConfig(portfolioData));

    document.getElementById('pieView').addEventListener('click', () => {
        switchChartType('pie', portfolioData);
        toggleActiveButton('pieView');
    });

    document.getElementById('barView').addEventListener('click', () => {
        switchChartType('bar', portfolioData);
        toggleActiveButton('barView');
    });

    return currentChart;
}

/**
 * Safely switches between chart types
 * @param {string} type - 'pie' or 'bar'
 * @param {Array} data - Portfolio data
 */
function switchChartType(type, data) {
    const ctx = document.getElementById('portfolioChart').getContext('2d');
    if (currentChart) {
        currentChart.destroy();
    }
    const config = type === 'pie' ? createPieChartConfig(data) : createBarChartConfig(data);
    currentChart = new Chart(ctx, config);
}
/**
 * Extracts portfolio data from the existing table in the DOM
 * This avoids making additional API calls since the data is already available
 */
/**
 * Extracts portfolio data from the existing table in the DOM
 */
function extractPortfolioData() {
    const rows = document.querySelectorAll('#portfolioTable tbody tr');
    const data = [];

    rows.forEach(row => {
        const profitLossText = row.querySelector('.profit-loss').textContent;
        const profitLossValue = parseFloat(profitLossText.split('(')[0].trim().replace(/[^0-9.-]+/g, ''));

        const item = {
            name: row.querySelector('.crypto-name').textContent.trim(),
            amount: parseFloat(row.querySelector('td:nth-child(2) .display-value').textContent),
            currentValue: parseFloat(row.querySelector('.current-value').textContent.replace(/[^0-9.-]+/g, '')),
            profitLoss: profitLossValue
        };
        data.push(item);
    });

    return data;
}

//*Creates configuration for bar chart visualization*/
function createBarChartConfig(data) {
    const currency = document.getElementById('currencySelect').value;

    // Calculate the maximum absolute value for setting scale
    const maxAbsValue = Math.max(...data.map(item => Math.abs(item.profitLoss)));

    return {
        type: 'bar',
        data: {
            labels: data.map(item => item.name),
            datasets: [{
                label: 'Profit/Loss',
                data: data.map(item => item.profitLoss), // Use profit/loss instead of current value
                backgroundColor: data.map(item =>
                    item.profitLoss >= 0 ? 'rgba(40, 167, 69, 0.5)' : 'rgba(220, 53, 69, 0.5)'
                ),
                borderColor: data.map(item =>
                    item.profitLoss >= 0 ? 'rgb(40, 167, 69)' : 'rgb(220, 53, 69)'
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
                    suggestedMin: -maxAbsValue, // Set minimum to negative of max value
                    suggestedMax: maxAbsValue,  // Set maximum to max value
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)',
                        zeroLineColor: 'rgba(0, 0, 0, 0.25)',
                        zeroLineWidth: 2
                    },
                    ticks: {
                        callback: value => formatCurrency(value, currency)
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
                        label: context => {
                            const value = context.raw;
                            const formattedValue = formatCurrency(value, currency);
                            const percentageChange = ((value / data[context.dataIndex].currentValue) * 100).toFixed(2);
                            return `${formattedValue} (${percentageChange}%)`;
                        }
                    }
                },
                legend: {
                    display: false // Hide legend since we're only showing one dataset
                }
            }
        }
    };
}


/**
 * Creates configuration for pie chart visualization
 */
function createPieChartConfig(data) {
    const currency = document.getElementById('currencySelect').value;

    return {
        type: 'pie',
        data: {
            labels: data.map(item => item.name),
            datasets: [{
                data: data.map(item => Math.abs(item.currentValue)),
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(153, 102, 255, 0.5)',
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)',
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: context => {
                            const value = context.raw;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${context.label}: ${formatCurrency(value, currency)} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    };
}

/**
 * Determines the type of sorting to be applied for each column
 */
function getSortType(columnIndex) {
    const typeMap = {
        0: 'text',      // Cryptocurrency name
        1: 'number',    // Amount
        2: 'number',    // Purchase Price
        3: 'date',      // Purchase Date
        4: 'number',    // Current Price
        5: 'number',    // Current Value
        6: 'number'     // Profit/Loss
    };
    return typeMap[columnIndex] || 'text';
}


/**
 * Extracts and formats cell values for sorting
 */
function getCellValue(row, columnIndex, sortType) {
    const cell = row.cells[columnIndex];
    const displayValue = cell.querySelector('.display-value');
    const value = displayValue ? displayValue.textContent : cell.textContent;

    switch (sortType) {
        case 'number':
            return parseFloat(value.replace(/[^0-9.-]+/g, '')) || 0;
        case 'date':
            return new Date(value);
        default:
            return value.trim().toLowerCase();
    }
}

/**
 * Toggles active state of chart view buttons
 */
function toggleActiveButton(activeId) {
    document.querySelectorAll('.btn-group .btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(activeId).classList.add('active');
}

// Add necessary styles
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
`;
/**
 * Creates and adds a sort indicator span element to a table header
 */
function addSortIndicator(th) {
    // Check if indicator already exists
    if (!th.querySelector('.sort-indicator')) {
        const indicator = document.createElement('span');
        indicator.className = 'sort-indicator';
        indicator.textContent = '⇅';
        th.appendChild(indicator);
    }
}

/**
 * Updates the sort indicator for a header
 */
function updateSortIndicator(header, direction) {
    const indicator = header.querySelector('.sort-indicator');
    if (indicator) {
        indicator.textContent = direction === 'asc' ? '↑' : direction === 'desc' ? '↓' : '⇅';
    }
}

/**
 * Initializes sorting functionality for the portfolio table
 */
function initializeTableSorting() {
    const table = document.getElementById('portfolioTable');
    const thead = table.querySelector('thead');

    thead.querySelectorAll('th').forEach((th, index) => {
        // Skip the Actions column
        if (index < thead.querySelectorAll('th').length - 1) {
            th.style.cursor = 'pointer';
            th.dataset.sortDirection = 'none';
            th.dataset.sortType = getSortType(index);

            // Add sort indicator
            addSortIndicator(th);

            th.addEventListener('click', () => sortTable(index, th));
        }
    });
}

/**
 * Sorts the table based on the selected column
 */
function sortTable(columnIndex, header) {
    const table = document.getElementById('portfolioTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Reset other headers
    table.querySelectorAll('th').forEach(th => {
        if (th !== header) {
            th.dataset.sortDirection = 'none';
            updateSortIndicator(th, 'none');
        }
    });

    // Update sort direction
    const currentDirection = header.dataset.sortDirection;
    const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
    header.dataset.sortDirection = newDirection;
    updateSortIndicator(header, newDirection);

    // Sort the rows
    const sortType = header.dataset.sortType;
    rows.sort((rowA, rowB) => {
        const valueA = getCellValue(rowA, columnIndex, sortType);
        const valueB = getCellValue(rowB, columnIndex, sortType);

        // Handle undefined or null values
        if (!valueA && valueA !== 0) return 1;
        if (!valueB && valueB !== 0) return -1;

        if (valueA < valueB) return newDirection === 'asc' ? -1 : 1;
        if (valueA > valueB) return newDirection === 'asc' ? 1 : -1;
        return 0;
    });

    // Update the table
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
}

// Rest of the code remains the same...

// Initialize features when document is ready
// Initialize features when document is ready

document.addEventListener('DOMContentLoaded', () => {
    const chartScript = document.createElement('script');
    chartScript.src = 'https://cdn.jsdelivr.net/npm/chart.js';
    document.head.appendChild(chartScript);

    chartScript.onload = () => {
        try {
            initializePortfolioChart();
            initializeTableSorting(); // Add this line to initialize sorting
        } catch (error) {
            console.error('Error initializing portfolio features:', error);
            const chartContainer = document.querySelector('#portfolioChart')?.closest('.card');
            if (chartContainer) {
                chartContainer.innerHTML = `
                    <div class="alert alert-warning m-3">
                        Unable to load portfolio visualization. Please try refreshing the page.
                    </div>
                `;
            }
        }
    };

    // Add the styles to the document
    const styleSheet = document.createElement('style');
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);
});