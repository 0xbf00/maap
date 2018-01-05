from bundle.application import Application


class GenericBundle(Application):
    """If a bundle could not be identified as either being
    an application or a framework, this code is used.

    A generic bundle has simply the same structure as a
    ordinary application. However, it obviously does not have
    a receipt and is neither from the Mac App Store."""

    def app_store_receipt_path(self):
        raise NotImplementedError

    def is_mas_app(self):
        raise NotImplementedError
