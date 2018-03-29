import hashlib
from itertools import cycle


class VigenerCipher:
    def __init__(self):
        self.alph_size = 2 ** 16

    def encrypt(self, block_item, sub_key):
        return (block_item + sub_key) % self.alph_size

    def decrypt(self, block_item, sub_key):
        return (block_item - sub_key) % self.alph_size


class StandartEncryptionModes:
    def __init__(self, key, block_len):
        self.key = self.key256(str(key).encode('utf-8'))
        self.block_len = block_len

    def __get_iter_key(self):
        key_cycle = cycle(iter(self.key))
        for sub_key in key_cycle:
            yield ord(sub_key)

    def __get_block_stream(self, text_stream):
        iter_flag = True
        while iter_flag:
            block = []
            try:
                for i in range(self.block_len):
                    block.append(next(text_stream))
            except StopIteration:
                while len(block) < self.block_len and len(block) is not 0:
                    block.append(32)
                iter_flag = False
            if len(block) is not 0:
                yield block

    def ecb_crypt(self, text_stream, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        yield from [subc_f(item, next(kstream)) for block in bstream for item in block]

    def cbc_encrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        temp = None
        for block in bstream:
            temp = [subc_f(item, next(kstream))
                          for item in [(item1 ^ item2) for item1, item2 in zip(init_block, block)]]
            init_block = iter(temp)
            yield from temp

    def cbc_decrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            yield from [item1 ^ item2
                        for item1, item2 in zip(init_block, [subc_f(item, next(kstream)) for item in block])]
            init_block = block

    def cfb_encrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            init_block = [item1 ^ item2
                          for item1, item2 in zip(block, [subc_f(item, next(kstream)) for item in init_block])]
            yield from init_block

    def cfb_decrypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            yield from [item1 ^ item2
                        for item1, item2 in zip(block, [subc_f(item, next(kstream)) for item in init_block])]
            init_block = block

    def ofb_crypt(self, text_stream, init_block, subc_f):
        kstream = self.__get_iter_key()
        bstream = self.__get_block_stream(text_stream)
        for block in bstream:
            init_block = [subc_f(item, next(kstream)) for item in init_block]
            yield from [item1 ^ item2 for item1, item2 in zip(block, init_block)]

    @staticmethod
    def key256(key):
        return hashlib.sha256(key).hexdigest()
