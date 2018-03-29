import os
import time
import threading
import datetime
import random

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gio, GLib, Gtk, GObject

from generator import RSAKeyPairGenerator
from rsacrypt import RSACrypt
from lib.lab3 import BlockCipherUtil
from lib.ciplib import StandartEncryptionModes, VigenerCipher


class RSAWindow:

    def __init__(self):
        self.ui_file = os.path.join(os.getcwd(), 'rsa.glade')
        self.builder = Gtk.Builder()
        self.builder.add_from_file(self.ui_file)
        signals_handler ={
            'gtk_main_quit': Gtk.main_quit,
            'on_generate_button_clicked': self.on_generate_button_clicked,
            'on_enc_button_clicked': self.on_enc_button_clicked,
            'on_dec_button_clicked': self.on_dec_button_clicked,
            'gtk_widget_destroy': Gtk.Widget.destroy,
        }


        self.builder.connect_signals(signals_handler)

        self.window = self.builder.get_object('window1')
        self.passwrd_entry = self.builder.get_object('seed_entry')
        self.open_file = self.builder.get_object('open_filechooserbutton')
        self.close_file = self.builder.get_object('close_filechooserbutton')
        self.enc_file = self.builder.get_object('enc_filechooserbutton')
        self.dec_file = self.builder.get_object('dec_filechooserbutton')
        self.enc_btn = self.builder.get_object('enc_button')
        self.dec_btn = self.builder.get_object('dec_button')
        self.gen_btn = self.builder.get_object('generate_button')
        self.status = self.builder.get_object('statusbar1')
        self.context_id = self.status.get_context_id("Statusbar example")

        self.messagedialog = self.builder.get_object('messagedialog1')
        self.msg_label = self.builder.get_object('msg_label')

        self.window.show_all()

    def on_generate_button_clicked(self):
        open_filename = self.open_file.get_filename()
        close_filename = self.close_file.get_filename()

        try:
            self.status.push(self.context_id, 'Generating keys...')
            kpg = RSAKeyPairGenerator()
            open_key, close_key = kpg.generate_keys()

            self.status.push(self.context_id, 'Keys created. Writing them to files...')

            if open_filename:
                with open(open_filename, 'w') as f:
                    f.write(str(open_key[0]) + '\n')
                    f.write(str(open_key[1]))
                    f.close()
            else:
                with open(os.path.join(os.getcwd(), 'open_key'), 'w') as f:
                    f.write(str(open_key[0]) + '\n')
                    f.write(str(open_key[1]))
                    f.close()

            if close_filename:
                with open(close_filename, 'w') as f:
                    f.write(str(close_key[0]) + '\n')
                    f.write(str(close_key[1]))
                    f.close()
            else:
                with open(os.path.join(os.getcwd(), 'close_key'), 'w') as f:
                    f.write(str(close_key[0]) + '\n')
                    f.write(str(close_key[1]))
                    f.close()

            self.status.push(self.context_id, 'Готово! Генерация пары ключей.')

            self.msg_label.set_text('Done!')
            self.messagedialog.run()

        except Exception:
            self.status.push(self.context_id, 'Err!')


    def on_enc_button_clicked(self, args):
        open_filename = self.open_file.get_filename()
        close_filename = self.close_file.get_filename()
        enc_filename = self.enc_file.get_filename()
        dec_filename = self.dec_file.get_filename()

        rsac = RSACrypt()
        rsac.read_keys(open_key_filename=open_filename, private_key_filename=None)

        with open(enc_filename, 'r') as f:
            passwrd = f.read()
            f.close()

        passwrd_stream = rsac.encrypt(iter(map(ord, passwrd)))

        if dec_filename:
            with open(dec_filename, 'w') as f:
                for ch in passwrd_stream:
                    f.writelines(str(ch) + '\n')
        else:
            with open(enc_filename + '.cod', 'w') as f:
                for ch in passwrd_stream:
                    f.writelines(str(ch) + '\n')

        self.status.push(self.context_id, 'Готово! Шифрование закончено.')

    def on_dec_button_clicked(self, args):
        open_filename = self.open_file.get_filename()
        close_filename = self.close_file.get_filename()
        enc_filename = self.enc_file.get_filename()
        dec_filename = self.dec_file.get_filename()

        rsac = RSACrypt()
        rsac.read_keys(open_key_filename=None, private_key_filename=close_filename)

        with open(dec_filename, 'r') as f:
            passwrd = f.read()
            f.close()

        passwrd = passwrd.split('\n')
        if passwrd[-1:][0] is '':
            passwrd = passwrd[:-1]

        passwrd_stream = rsac.decrypt(map(int, passwrd))

        if enc_filename:
            with open(enc_filename, 'w') as f:
                for ch in map(chr, passwrd_stream):
                    f.write(ch)
        else:
            with open(dec_filename + '.dec', 'w') as f:
                for ch in map(chr, passwrd_stream):
                    f.write(ch)

        self.status.push(self.context_id, 'Готово! Дешифрование закончено.')



if __name__ == '__main__':
    w = RSAWindow()
    Gtk.main()
