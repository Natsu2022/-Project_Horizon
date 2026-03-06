class BaseScanner:

    def __init__(self, context):
        self.context = context

    def scan(self):
        raise NotImplementedError()