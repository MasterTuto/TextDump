# -*- coding: utf-8 -*-

import base64
import hashlib
import Tkinter
from PIL import ImageTk, Image
import tkMessageBox
import findmyhash

janela = Tkinter.Tk()
janela.configure(background='white')
janela.geometry("350x300")
janela.title("TextDump")

binaryvar = textPlanovar = hexadecimalvar = decimalvar = base64evar = base32var = base16var = md5var = sha1var = None
encrypt = True

img = ImageTk.PhotoImage(Image.open('noname.jpg'))
panel = Tkinter.Label(janela, image = img, background='white')
panel.grid(row=1, column=2)


class Tudo(object):
	def mudar_uso(self, tipo, textPlano, binary, hexadecimal, decimal, base64e, base32, md5, sha1, iniciar):

		self.textPlano   = textPlano
		self.binary      = binary
		self.hexadecimal = hexadecimal
		self.decimal     = decimal
		self.base64e     = base64e
		self.base32      = base32
		self.md5         = md5
		self.sha1        = sha1
		
		tipos = [self.textPlano, self.binary, self.hexadecimal, self.decimal, self.base64e, self.base32, self.md5, self.sha1]

		for i in tipos:
			if tipo == i:
				i.configure(state='normal')
				i.update()
				qual_tipo = tipos.index(tipo)
			else:
				i.configure(state='readonly')
				i.update()

			if tipo == self.md5:
				self.botaomd5['state'] = 'normal'
			else:
				self.botaomd5['state'] = 'disable'

		self.qual_tipo = qual_tipo

	def adicionar(self):
		global textPlanovar, binaryvar, hexadecimalvar, decimalvar, base64evar, base32var, md5var, sha1var

		tipo = Tkinter.IntVar()

		Tkinter.Label(janela, text="Texto Plano: ", background='white').grid(row=2, column=1)
		textPlanovar = Tkinter.StringVar()
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(textPlano, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=1).grid(row=2, column=3)
		textPlano = Tkinter.Entry(janela, state='readonly', textvariable=textPlanovar)
		textPlano.grid(row=2, column=2)

		Tkinter.Label(janela, text="Binario: ", background='white').grid(row=3, column=1)
		binaryvar = Tkinter.StringVar()
		binary = Tkinter.Entry(janela, state="readonly", textvariable=binaryvar)
		binary.grid(row=3, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(binary, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=2).grid(row=3, column=3)

		Tkinter.Label(janela, text="Hexadecimal: ", background='white').grid(row=4, column=1)
		hexadecimalvar = Tkinter.StringVar()
		hexadecimal = Tkinter.Entry(janela, state="readonly", textvariable=hexadecimalvar)
		hexadecimal.grid(row=4, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(hexadecimal, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=3).grid(row=4, column=3)

		Tkinter.Label(janela, text="Decimal: ", background='white').grid(row=5, column=1)
		decimalvar = Tkinter.StringVar()
		decimal = Tkinter.Entry(janela, state="readonly", textvariable=decimalvar)
		decimal.grid(row=5, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(decimal, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=4).grid(row=5, column=3)

		Tkinter.Label(janela, text="Base64: ", background='white').grid(row=6, column=1)
		base64evar = Tkinter.StringVar()
		base64e = Tkinter.Entry(janela, state="readonly", textvariable=base64evar)
		base64e.grid(row=6, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(base64e, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=5).grid(row=6, column=3)

		Tkinter.Label(janela, text="Base32: ", background='white').grid(row=7, column=1)
		base32var = Tkinter.StringVar()
		base32 = Tkinter.Entry(janela, state="readonly", textvariable=base32var)
		base32.grid(row=7, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(base32, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=6).grid(row=7, column=3)

		Tkinter.Label(janela, text="md5: ", background='white').grid(row=8, column=1)
		md5var = Tkinter.StringVar()
		md5 = Tkinter.Entry(janela, state="readonly", textvariable=md5var)
		md5.grid(row=8, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(md5, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=7).grid(row=8, column=3)
		botaomd5 = Tkinter.Button(janela, text="Decriptar", command=lambda: Converter(md5.get()).md5(), state='disable')
		botaomd5.grid(row=8, column=4)
		self.botaomd5 = botaomd5

		Tkinter.Label(janela, text="sha1: ", background='white').grid(row=9, column=1)
		sha1var = Tkinter.StringVar()
		sha1 = Tkinter.Entry(janela, state="readonly", textvariable=sha1var)
		sha1.grid(row=9, column=2)
		Tkinter.Radiobutton(janela, var=tipo, background='white', command=lambda: self.mudar_uso(sha1, textPlano, binary, hexadecimal, decimal,
			base64e, base32, md5, sha1, iniciar), value=8).grid(row=9, column=3)
		# iniciar = Tkinter.Button(janela, text="Decriptar", command=lambda: Converter(md5.get()).sha1())
		# iniciar.grid(row=9, column=4)

		self.textPlano = textPlano
		self.textPlanovar = textPlano

		self.binaryvar = binaryvar
		self.binary = binary

		self.hexadecimalvar = hexadecimalvar
		self.hexadecimal = hexadecimal

		self.decimalvar = decimalvar
		self.decimal = decimal

		self.base64evar = base64evar
		self.base64e = base64e

		self.base32var = base32var
		self.base32 = base32

		self.md5var = md5var
		self.md5 = md5

		self.sha1var = sha1var
		self.sha1 = sha1

		iniciar = Tkinter.Button(janela, text="Converter", command=lambda: self.verificar_e_adicionar(self.qual_tipo))
		iniciar.grid(row=10, column=2)
		self.iniciar = iniciar

	def verificar_e_adicionar(self, qual_tipo):
		if qual_tipo == 0:
			Converter(self.textPlano.get()).encrypt()
		elif qual_tipo == 1:
			Converter(self.binary.get()).binary()
		elif qual_tipo == 2:
			Converter(self.hexadecimal.get()).hexadecimal()
		elif qual_tipo == 3:
			Converter(self.decimal.get()).decimal()
		elif qual_tipo == 4:
			Converter(self.base64evar.get()).base64()
		elif qual_tipo == 5:
			Converter(self.base32.get()).base32()
		elif qual_tipo == 6:
			Converter(self.md5.get()).md5()
		elif qual_tipo == 7:
			Converter(self.sha1.get()).sha1()


class Converter():
	def __init__(self, gotit):
		self.gotit = gotit

	def encrypt(self):
		textPlanovar.set(self.gotit)

		try:
			binario = [ord(c) for c in self.gotit]
			binario = [str(bin(c)) for c in binario]
			binaryvar.set(filter(lambda x: x.isdigit(), ''.join(binario)))

			hexadecimalvar.set(base64.b16encode(self.gotit))

			deci = [str(ord(c)) for c in self.gotit]
			decimalvar.set(''.join(deci))

			base64evar.set(base64.b64encode(self.gotit))

			base32var.set(base64.b32encode(self.gotit))

			md5var.set(hashlib.md5(self.gotit).hexdigest())

			sha1var.set(hashlib.sha1(self.gotit).hexdigest())
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def base64(self):
		try:
			word = base64.b64decode(self.gotit)
			Converter(word).encrypt()
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def base32(self):
		try:
			word = base64.b32decode(self.gotit)
			Converter(word).encrypt()
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def binary(self):
		try:
			splitted = []
			num, num2 = 0, 8
			while True:
				if num2 < len(self.gotit) + 1:
					splitted.append(self.gotit[num:num2])
					num += 8
					num2 += 8
				else:
					break
			splitted = [chr(int("0b"+s, 2)) for s in splitted]
			word =  ''.join(filter(lambda x: x.isdigit() or x.isalpha(), splitted))
			Converter(word).encrypt()
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def hexadecimal(self):
		try:
			word = base64.b16decode(self.gotit)
			Converter(word).encrypt()
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def decimal(self):
		try:
			splitted = []
			num, num2 = 0, 2
			while True:
				if num2 < len(self.gotit) + 1:
					splitted.append(self.gotit[num:num2])
					num += 2
					num2 += 2
				else:
					break
			splitted = [chr(int(s)) for s in splitted]
			word =  ''.join(splitted)
			Converter(word).encrypt()
		except:
			tkMessageBox.showerror("Erro", "Valor inválido!")

	def md5(self):
		tkMessageBox.showwarning('Aviso', "O processo pode ser um pouco demorado, tenha paciência.")
		
		word = findmyhash.main('md5', self.gotit)

		if not word:
			tkMessageBox.showwarning("Aviso", "Hash nao encontrada em nenhuma database!")
		else:
			Converter(word).encrypt()

	def sha1(self):
		tkMessageBox.showwarning('Aviso', "O processo pode ser um pouco demorado, tenha paciência.")
		word = findmyhash.main('sha1', self.gotit)

		if word == 'bug':
			tkMessageBox.showerror("Erro", "Um bug foi encontrado!\nContacte a bloglaxmarcaellugar@gmail.com para mais informações")

		Converter(word).encrypt()

Tudo().adicionar()

janela.mainloop()
