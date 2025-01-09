import { formatCurrency } from './utils.js';
import { ApiService } from './api-service.js'

// La funzione principale che aggiorna il valore del portfolio rimane quasi identica,
// ma ora utilizza il valore del selettore della valuta se disponibile
async function updatePortfolioValue() {
    const valueElement = document.getElementById('portfolio-value-root');
    if (!valueElement) return;

    try {
        // Prima proviamo a ottenere la valuta dal selettore nell'interfaccia
        let currentCurrency;
        const currencySelect = document.getElementById('currencySelect');

        if (currencySelect) {
            // Se il selettore esiste, usa il suo valore
            currentCurrency = currencySelect.value;
        } else {
            // Altrimenti, ottieni la valuta dalle preferenze dell'utente
            currentCurrency = ApiService.getCurrentCurrency();
        }

        // Manteniamo la precisione decimale come nell'originale
        const rawValue = valueElement.dataset.value;
        const totalValue = parseFloat(parseFloat(rawValue).toFixed(2));

        const lastUpdate = valueElement.dataset.lastUpdate;

        // Manteniamo lo stesso layout HTML dell'originale
        valueElement.innerHTML = `
            <div class="bg-white rounded-lg shadow p-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h2 class="h4 mb-0">Total Portfolio Value</h2>
                    <button class="btn btn-link p-0" onclick="window.location.reload()">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                <div class="d-flex align-items-baseline gap-2">
                    <span class="h2 mb-0" id="formatted-portfolio-value">${formatCurrency(totalValue, currentCurrency)}</span>
                </div>
                <p class="text-muted small mb-0 mt-2">
                    Last updated: ${lastUpdate}
                </p>
            </div>
        `;
    } catch (error) {
        console.error('Error updating portfolio value:', error);
    }
}

// Manteniamo l'inizializzazione al caricamento del documento
document.addEventListener('DOMContentLoaded', updatePortfolioValue);

// Esportiamo la funzione per l'uso in altri moduli
export { updatePortfolioValue };