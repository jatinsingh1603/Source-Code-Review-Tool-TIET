def edit(req, doc):
    title = req.args["title"]
    if not has_permission(req.user, doc):
        raise Forbidden()
    doc.title = title
    return doc
