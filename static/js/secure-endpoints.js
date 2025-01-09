// secure-endpoints.js

/**
 * @fileoverview Secure endpoint configuration and validation module
 * 
 * This module provides a secure way to manage API endpoints with:
 * - Centralized endpoint configuration
 * - Runtime validation
 * - Pattern matching for endpoint validation
 * - Error handling and logging
 * - Protection against endpoint manipulation
 */

// Freeze endpoint configurations to prevent runtime modifications
const ENDPOINTS = Object.freeze({
    AUTH: {
        LOGIN: '/auth/login',
        LOGOUT: '/auth/logout',
        CALLBACK: '/auth/callback'
    },
    PORTFOLIO: {
        ADD: '/api/portfolio/add',
        UPDATE: '/api/portfolio/update',
        DELETE: '/api/portfolio/delete',
        LIST: '/api/portfolio'
    },
    PREFERENCES: {
        CURRENCY: '/api/preferences/currency'
    },
    SECURITY: {
        TOKEN: '/api/token',
        TOKEN_STATUS: '/api/token/status',
        TOKEN_CLEANUP: '/api/token/cleanup',
        CSRF_TOKEN: '/api/csrf/token',
        CSRF_NONCE: '/api/csrf/nonce'
    },
    NAVIGATION: {
        HOME: '/navigate-home'
    }
});

// Regular expression for validating endpoint patterns
const ENDPOINT_PATTERN = /^\/(?:api\/)?[a-zA-Z0-9-_/]+$/;

class EndpointSecurityManager {
    constructor() {
        // Create a private validated endpoints cache
        this._validatedEndpoints = new Map();

        // Validate all endpoints on initialization
        this._validateAllEndpoints();
    }

    /**
     * Validates all configured endpoints
     * @private
     * @throws {Error} If any endpoint is invalid
     */
    _validateAllEndpoints() {
        const validateNestedEndpoints = (obj, path = '') => {
            Object.entries(obj).forEach(([key, value]) => {
                const currentPath = path ? `${path}.${key}` : key;

                if (typeof value === 'string') {
                    if (!this._isValidEndpoint(value)) {
                        throw new Error(`Invalid endpoint pattern: ${value} at ${currentPath}`);
                    }
                    this._validatedEndpoints.set(value, true);
                } else if (typeof value === 'object' && value !== null) {
                    validateNestedEndpoints(value, currentPath);
                }
            });
        };

        validateNestedEndpoints(ENDPOINTS);
    }

    /**
     * Validates an individual endpoint pattern
     * @private
     * @param {string} endpoint - Endpoint to validate
     * @returns {boolean} True if endpoint is valid
     */
    _isValidEndpoint(endpoint) {
        return typeof endpoint === 'string' &&
            ENDPOINT_PATTERN.test(endpoint) &&
            !endpoint.includes('..') &&
            endpoint.length <= 255;
    }

    /**
     * Safely retrieves an endpoint URL
     * @param {string} category - Endpoint category
     * @param {string} name - Endpoint name
     * @param {Object} params - Optional parameters for dynamic endpoints
     * @returns {string} Validated endpoint URL
     * @throws {Error} If endpoint is invalid or not found
     */
    getEndpoint(category, name, params = {}) {
        try {
            // Verify category exists
            if (!ENDPOINTS[category]) {
                throw new Error(`Invalid endpoint category: ${category}`);
            }

            // Get base endpoint
            const endpoint = ENDPOINTS[category][name];
            if (!endpoint) {
                throw new Error(`Invalid endpoint name: ${name} in category ${category}`);
            }

            // For dynamic endpoints, validate and substitute parameters
            let finalEndpoint = endpoint;
            if (Object.keys(params).length > 0) {
                finalEndpoint = Object.entries(params).reduce(
                    (url, [key, value]) => {
                        // Validate parameter values
                        if (typeof value !== 'string' && typeof value !== 'number') {
                            throw new Error(`Invalid parameter type for ${key}`);
                        }

                        const safeValue = encodeURIComponent(String(value));
                        return url.replace(`:${key}`, safeValue);
                    },
                    endpoint
                );
            }

            // Validate final endpoint
            if (!this._isValidEndpoint(finalEndpoint)) {
                throw new Error(`Invalid generated endpoint: ${finalEndpoint}`);
            }

            return finalEndpoint;
        } catch (error) {
            console.error('Endpoint security error:', error);
            throw error;
        }
    }

    /**
     * Validates a complete URL against known endpoints
     * @param {string} url - URL to validate
     * @returns {boolean} True if URL matches a known endpoint
     */
    isValidUrl(url) {
        try {
            const parsedUrl = new URL(url, window.location.origin);
            const pathname = parsedUrl.pathname;

            // Check if pathname matches any validated endpoint
            return this._validatedEndpoints.has(pathname);
        } catch (error) {
            console.error('URL validation error:', error);
            return false;
        }
    }
}

// Export singleton instance
export const endpointManager = Object.freeze(new EndpointSecurityManager());

// Usage example with the ApiService:
/*
import { endpointManager } from './secure-endpoints';
import { ApiService } from './api-service';

class SecureApiService {
    async addToPortfolio(data) {
        const endpoint = endpointManager.getEndpoint('PORTFOLIO', 'ADD');
        return ApiService.safeFetch(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async updatePortfolioItem(id, data) {
        const endpoint = endpointManager.getEndpoint('PORTFOLIO', 'UPDATE', { id });
        return ApiService.safeFetch(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
}
*/