// static/js/api-service.js

/**
 * Service for handling all API communications
 */
export const ApiService = {
    /**
     * Fetch available cryptocurrencies from the server
     * @returns {Promise<Array>} List of available cryptocurrencies
     */
    async fetchCryptocurrencies() {
        const response = await fetch('/api/cryptocurrencies');
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch cryptocurrencies');
        }
        return data.data;
    },

    /**
     * Add a new cryptocurrency to the portfolio
     * @param {Object} cryptoData - Cryptocurrency data to add
     * @returns {Promise<Object>} Response from the server
     */
    async addCrypto(cryptoData) {
        const response = await fetch('/api/portfolio/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cryptoData)
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to add cryptocurrency');
        }
        return data;
    },

    /**
     * Update an existing cryptocurrency in the portfolio
     * @param {string} cryptoId - ID of the cryptocurrency to update
     * @param {Object} updateData - Updated cryptocurrency data
     */
    async updateCrypto(cryptoId, updateData) {
        const response = await fetch(`/portfolio/update/${cryptoId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updateData)
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to update cryptocurrency');
        }
        return data;
    },

    /**
     * Delete a cryptocurrency from the portfolio
     * @param {string} cryptoId - ID of the cryptocurrency to delete
     */
    async deleteCrypto(cryptoId) {
        const response = await fetch(`/portfolio/delete/${cryptoId}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to delete cryptocurrency');
        }
        return data;
    },

    /**
     * Get user's current currency preference
     * @returns {Promise<Object>} Response containing the preferred currency
     */
    async getCurrentCurrency() {
        const response = await fetch('/preferences/currency');
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch currency preference');
        }

        return data.preferred_currency;
    },

};
