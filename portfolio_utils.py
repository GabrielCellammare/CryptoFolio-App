# Portfolio Management


def calculate_portfolio_metrics(portfolio_item, current_price, currency='USD'):
    """
    Calculates various financial metrics for a portfolio item.

    Args:
        portfolio_item(dict): Portfolio item data containing:
            - amount(float): Quantity of cryptocurrency
            - purchase_price(float): Price at purchase
        current_price(float): Current price of the cryptocurrency
        currency(str, optional): Target currency. Defaults to 'USD'

    Returns:
        dict: Calculated metrics including:
            - current_price(float): Current cryptocurrency price
            - current_value(float): Current total value
            - profit_loss(float): Absolute profit/loss
            - profit_loss_percentage(float): Relative profit/loss percentage
            - currency(str): Currency used for calculations

    Raises:
        ValueError: If invalid numeric values provided
    """
    try:
        # Ensure the values are numeric
        amount = float(portfolio_item.get('amount', 0))
        purchase_price = float(portfolio_item.get('purchase_price', 0))

        # Ensure current_price is numeric
        current_price = float(current_price) if current_price else 0.0

        # No longer need currency conversion here because
        # prices already come in the correct currency from get_crypto_prices

        current_value = amount * current_price
        purchase_value = amount * purchase_price

        # Avoid division by zero
        profit_loss = current_value - purchase_value
        if purchase_value > 0:
            profit_loss_percentage = (current_value / purchase_value - 1) * 100
        else:
            profit_loss_percentage = 0

        return {
            'current_price': current_price,
            'current_value': current_value,
            'profit_loss': profit_loss,
            'profit_loss_percentage': profit_loss_percentage,
            'currency': currency
        }

    except Exception as e:
        print(f"Error in calculate_portfolio_metrics: {e}")
        # Return default values in case of error
        return {
            'current_price': 0,
            'current_value': 0,
            'profit_loss': 0,
            'profit_loss_percentage': 0,
            'currency': currency
        }
