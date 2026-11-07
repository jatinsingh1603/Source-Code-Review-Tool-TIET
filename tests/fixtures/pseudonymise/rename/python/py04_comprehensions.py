def pick(accounts, threshold):
    big = [acct for acct in accounts if acct.balance > threshold]
    names = {acct.owner: acct for acct in big}
    flags = {acct.owner for acct in big}
    total = sum(acct.balance for acct in big)
    return big, names, flags, total
