def total_due(customer):
    return customer.profile.billing.outstanding_amount + customer.profile.late_fee
