export const calculateExpiryDate = (purchaseDate, validityPeriod) => {
    try {
        if (!purchaseDate) {
            throw new Error('Purchase date is required');
        }

        if (!validityPeriod || !validityPeriod.unit || !validityPeriod.duration) {
            // Return a default expiry date (e.g., 1 year from purchase)
            const date = new Date(purchaseDate);
            date.setFullYear(date.getFullYear() + 1);
            return date;
        }

        const date = new Date(purchaseDate);
        const unit = validityPeriod.unit.toLowerCase();
        const duration = parseInt(validityPeriod.duration) || 0;

        switch (unit) {
            case 'days':
                date.setDate(date.getDate() + duration);
                break;
            case 'months':
                date.setMonth(date.getMonth() + duration);
                break;
            case 'years':
                date.setFullYear(date.getFullYear() + duration);
                break;
            default:
                // Default to 1 year if unit is invalid
                date.setFullYear(date.getFullYear() + 1);
        }

        return date;
    } catch (error) {
        console.error('Error calculating expiry date:', error);
        // Return a default date (1 year from purchase)
        const defaultDate = new Date(purchaseDate);
        defaultDate.setFullYear(defaultDate.getFullYear() + 1);
        return defaultDate;
    }
};