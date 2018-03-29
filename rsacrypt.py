class RSACrypt:
    def __init__(self):
        self.open_key = None
        self.private_key = None
        self.modular = None

    def read_keys(self, open_key_filename, private_key_filename):
        open_modular = None
        private_modular = None

        if open_key_filename:
            with open(open_key_filename, 'r') as f:
                self.open_key = int(f.readline())
                open_modular = int(f.readline())
                f.close()

        if private_key_filename:
            with open(private_key_filename, 'r') as f:
                self.private_key = int(f.readline())
                private_modular = int(f.readline())
                f.close()

        if open_modular:
            self.modular = open_modular
        if private_modular:
            self.modular = private_modular

    def qe2(self, x, y, n):
        s, t, u = 1, x, y
        while u:
            if u & 1:
                s = (s * t) % n
            u >>= 1
            t = (t * t) % n
        return s


    def encrypt(self, text):
        for ch in text:
            # yield (ch ** self.open_key) % self.modular
            yield self.qe2(ch, self.open_key, self.modular)

    def decrypt(self, encrypt_text):
        for ch in encrypt_text:
            # yield (ch ** self.private_key) % self.modular
            yield self.qe2(ch, self.private_key, self.modular)
