import random, html, sys, re, os, traceback, requests, subprocess
from urllib.parse import parse_qs
from datetime import datetime
from http import cookies
from math import log

from config import PREPEND, AUTH_USERS, AUTH_SERVER, SH_PATH

VERSION="0.1"
APPLICATION="mars"

GAME_HTML="""


"""

# meta tag from https://stackoverflow.com/questions/7073396/disable-zoom-on-input-focus-in-android-webpage
TERMINAL_HTML="""
<meta name="viewport" content="width=device-width, height=device-height,  initial-scale=1.0, user-scalable=no;user-scalable=0;"/>

<div class="game_output">
<form class="game_output" class="game_output">
	<textarea id="game_output" class="game_output" name="out" readonly>%(output)s</textarea>
</form></div>
	<script type="text/javascript">
		var TA = document.getElementById('game_output')
		TA.scrollTop = TA.scrollHeight
	</script>
<br />

<div class="game_input">
<div class="fast_game_input"><form method="post" class="fast_game_input">
	<input type="text" class="fast_game_input" name="in"
			autocomplete="off" autofocus />
	<button type="submit">Run</button>
</form></div>
<div class="multi_game_input"><form method="post" class="multi_game_input">
	<textarea class="multi_game_input" name="in"></textarea>
	<br />
	<button type="submit">Submit</button>
</form></div>
</div>
"""

def DP(strg):
	print(strg, file=sys.stderr)

def appver():
	return "%s %s" % (APPLICATION, VERSION)

def messageblock(lst):
	res=''
	sep = '<br /><hr /><br />'

	res += sep
	for item in lst:
		res += "<code>%s = %s</code><br />" % (item[0], str(item[1]))
	res += sep

	return res

def ok_html(doc, SR, extra_headers=[]):
	SR('200 Ok', [('Content-Type', 'text/html')] + extra_headers)
	return bytes(doc, "UTF-8")

def notfound_html(doc, SR):
	SR('404 Not Found', [('Content-Type', 'text/html')])
	return bytes(doc, "UTF-8")

def prepend():
	head=''
	for n in PREPEND:
		with open(n, 'r') as f:
			head += f.read()
	return head

def generate_html(doc, msgs, env, SR):
	page = prepend() + doc + messageblock(msgs)

	return ok_html(page, SR)

def get_token_from_cookie(env):
	US=None

	# get auth=$TOKEN from user cookie
	cookie_user_raw = env.get('HTTP_COOKIE', '')
	cookie_user = cookies.BaseCookie('')
	cookie_user.load(cookie_user_raw)

	auth = cookie_user.get('auth', cookies.Morsel())
	if auth.value is not None:
		return auth.value


def get_authorized_user(env):
	token = get_token_from_cookie(env)
	uri ='%s?token=%s' % (AUTH_SERVER, token)

	res = requests.get(uri, verify=False)

	DP('req to uri="%s" returned %s' % (uri, res.status_code))
	DP('content: %s' % res.text)
	
	if res.status_code == 200:
		split=res.text.split('=')
		if len(split) > 0:
			return split[1]

	return None

def generate_price(digits):

	# no 0s in start
	numbers = "12345689"
	dollars = "".join(random.choices(numbers, k=1))

	# no 7s ever
	numbers = "012345689"
	dollars  += "".join(random.choices(numbers, k=digits-1))


	res=''
	i=0
	for item in dollars[::-1]:
		if i != 0 and i % 3 == 0:
			res = item + "," + res
		else:	
			res = item + res
		i += 1
	cents = "".join(random.choices(numbers, k=2))
	final = "$" + res + "." + cents

	return final

def get_req_body_size(env):
	try:
		req_body_size = int(env.get('CONTENT_LENGTH', 0))
	except ValueError:
		req_body_size = 0
	
	return req_body_size

def is_post_req(env):
	return get_req_body_size(env) > 0

# input format: 
# INPUT := COMM | INPUT\nCOMM
# COMM := GAME | START_LINE | WARP_LINE | REPORT_LINE | DUMP_LINE
# GAME := "GAM"\nGAME_LINE "MAG"
# TYPE_IDENT := TYPE:IDENT
# GAME_LINE := TYPE_IDENT VAL\n | GAME_LINE TYPE:IDENT VAL\n
# IDENT :=~ [a-zA-Z]+
# TYPE := "poly" | "const"
# POLY := NUM:NUM | NUM:NUM/POLY
# CONST := [_0-9a-zA-Z]+
# NUM ~= [1-9]?[0-9]*
# VAL := POLY | CONST
# START_LINE := START | START <unix_timestamp>

TYPE_re		='(poly|const)'
IDENT_re	='[a-zA-Z ./:]+'
NUM_re		='[-0-9]?[0-9]+\.?[0-9]*'
POLY_re		='(%s:%s\/?)+' 	% (NUM_re, NUM_re)
CONST_re 	='[_0-9a-zA-Z ]+'
VAL_re 		='(%s|%s)' 	% (POLY_re, CONST_re)
TYPE_IDENT_re	='%s\w*%s'	% (TYPE_re, IDENT_re)
GAME_re		='GAM.*'
DROP_re		='DROP\W*(%s)?' % (NUM_re)
DUMP_re		='DUMP.*'
MAG_re		='GAM.*'	
GAME_LINE_re	='%s %s'	% (TYPE_IDENT_re, VAL_re)
START_LINE_re	='START\W*(%s)?'% (NUM_re)
WARP_LINE_re	='WARP\W*(%s)?'	% (NUM_re)
REPORT_LINE_re	='REPORT.*'
COMM_ST_NONE_re	='(\W*|%s|%s|%s|%s|%s|%s)' % (GAME_re, START_LINE_re, WARP_LINE_re, REPORT_LINE_re, DROP_re, DUMP_re)
COMM_ST_GAM_re 	='(%s|%s)' % (GAME_LINE_re, MAG_re)
COMM_re		='(%s|%s)'	% (COMM_ST_NONE_re, COMM_ST_GAM_re)

def just(reg):
	return '^%s$' % reg

def assert_valid(E, rex, data, info=''):
	DP('GAM validate %s by regex %s' % (data, rex))
	if info != '':
		info += ' '
	if re.search(just(rex), data) is None:
		E('%sargument matching %s' % (info, rex), '%s' % data, 'Invalid value')

class BadGamWarning(Exception):
	pass

class BadGamError(Exception):
	pass

class GamError(Exception):
	ERROR_FMT="""%(header)s
	line:\t%(line)d
	state:\t%(state_string)s (%(state)d)
	msg:\t%(message)s
"""
	def __init__(self, n=-1, st=-1, st_str='?', h='', m='undefined error'):
		self.line = n
		self.state = st
		self.state_string = st_str
		self.header = h
		self.message = m
		super().__init__(m)

	def __str__(self):
		return GamError.ERROR_FMT % {
			'header': 	self.header,
			'line': 	self.line,
			'state_string': self.state_string,
			'state':	self.state,
			'message':	self.message}

class GamParseError(GamError):
	PARSE_HEADER='Parse Error:'

	def __init__(self, msg='undefined parse error', n=-1, st=-1, st_str='?', tbl=None):
		if tbl:
			opt = '\npossible acts in %s:\n' % st_str
			for k in tbl:
				opt += '  %s' % k
			msg += opt

		super().__init__(n=n, st=st, st_str=st_str, \
			h=GamParseError.PARSE_HEADER, m=msg)

	def __str__(self):
		return super().__str__()


class GamLexxError(GamError):
	LEXX_HEADER='Lexx Error:'

	def __init__(self, msg='undefined lexx error', n=-1, st=-1, st_str='?'):
		super().__init__(n=n, st=st, st_str=st_str, \
			h=GamLexxError.LEXX_HEADER, m=msg)

	def __str__(self):
		return super().__str__()

class GamException(GamError):
	def __init__(self, gs, msg):
		self.gs = gs
		self.n = gs.step_counter
		self.c = gs.comms[self.n]
		self.s = gs.stack
		super().__init__(n=self.n, st=len(self.s),\
			st_str=self.c.line.line,\
			h='Runtime Exception:', m=msg)

	def string(self):
		output = super().__str__()
		output += 'stack: %s\n' % str(self.s)
		#tb = traceback.format_exc()
		#output += '%s\n' % str(tb)
		output += '======[NOT SAVED]======\n'
		return output
		


class GamNam:
	def __init__(self, E, typ, nam):
		assert_valid(E, TYPE_IDENT_re, '%s %s' % (typ, nam))
		self.typ = typ
		self.nam = nam

	def __str__(self):
		return '%s:%s' % (self.typ, self.nam)

	def __repr__(self):
		return 'GamNam("%s:%s")' % (self.typ, self.nam)

	def __hash__(self):
		return hash('%s:%s' % (self.typ, self.nam))

# doesn't do anything by itself: parent to other value types
class GamVal:
	def __init__(self, E, val):
		assert_valid(E, VAL_re, val, info='Generic Val')

class GamValPoly(GamVal):
	def __init__(self, E, val):
		super().__init__(E, val)
		assert_valid(E, POLY_re, val, info='Polynomial')
		pairs_raw = val.split('/')
		self.raw_pairs = [(float(pair[0]), float(pair[1])) \
			for pair in [pair_raw.split(':') \
				for pair_raw in pairs_raw]]
		self.pairs = {}
		for p in self.raw_pairs:
			v = self.pairs.get(p[1], None)
			if v is None:
				self.pairs[p[1]] = 0
			self.pairs[p[1]] += p[0]

	def _str(self, fmt, sep):
		base = ''
		for p in self.pairs:
			base += fmt % (self.pairs[p], p, sep)

		# snip off terminating $sep
		base = base[:len(base)-len(sep)]

		return base

	def __add__(self, rhs):
		lhs_pairs = [p for p in self.pairs]
		for p in rhs.pairs:
			r_e = p[1]
			r_c = p[0]
			if self.pairs.get(r_e, None) is None:
				p.pairs[r_e] = 0
			lhs_pairs[r_e] += r_c

		raw_pairs = []
		for p in lhs_pairs:
			raw_pairs += [(lhs_pairs[p], p)]
		
		return GamValPoly(raw_pairs)

	def f(self, t):
		total=0
		try:
			for p in self.pairs:
				total += self.pairs[p] * (t ** p)
				DP('POLY TERM %g = %g * t ^ %g' % (total, self.pairs[p], p))
			return '%g' % total
		except OverflowError:
			return 'overflow'

	def __str__(self):
		return 'f(t+w) = %s' % self._str('(%g)*t^(%g)%s', ' + ')

	def __repr__(self):
		return 'GamValPoly([%s])' % self._str('("%g","%g")%s', ',')

class GamValConst(GamVal):
	def __init__(self, E, val):
		super().__init__(E, val)
		assert_valid(E, CONST_re, val, info='Constant')
		self.val = val

	def f(self, t):
		return self.val

	def __str__(self):
		return str(self.val)

	def __repr__(self):
		return 'GameValConst(%s)' % repr(self.val)
	
class GamLine:
	COUNTER = 0

	@classmethod
	def do_count(cls):
		cls.COUNTER += 1
		return cls.COUNTER

	NULL=chr(0)
	CH_OTH=1<<0	# character not included
	CH_ALP=1<<1	# alphabetic character (both cases)
	CH_DIG=1<<2	# numeric character
	CH_SPC=1<<3	# whitespace character
	CH_COL=1<<4	# colon (:)
	CH_SLS=1<<5	# slash (/)
	CH_DOT=1<<6	# dot (.)
	CH_QUT=1<<7	# quote (")
	CH_COM=1<<8	# comma (,)
	CH_BNG=1<<9	# exclamation point, aka bang (!)
	CH_DSH=1<<10	# comma (,)
	CH_RAN=1<<11	# right angle bracket (>)
	CH_LAN=1<<12	# left angle backet (<)
	CH_RSQ=1<<13	# right square bracket (])
	CH_LSQ=1<<14	# left square backet ([)
	CH_AAT=1<<15	# at symbol (@)
	CH_NIL=1<<16	# GamLine.NULL
	CH_SCL=1<<17	# semicolon (;)
	CH_EQL=1<<18	# equal sign (=)
	CH_RPR=1<<19	# right parenthesis ())
	CH_LPR=1<<20	# left parenthesis (()
	CH_PLS=1<<21	# plus (+)
	CH_UND=1<<22	# underscore (_)
	CH_SEP=1<<23	# vertical separator (|)
	# consider , and  ! to be part of string text input domain
	CH_TXT=CH_ALP + CH_COM + CH_BNG + CH_RAN + CH_LAN + CH_RSQ + CH_LSQ \
		      + CH_SCL + CH_RPR + CH_LPR + CH_EQL + CH_PLS + CH_UND \
		      + CH_SEP + CH_AAT + CH_DSH
	CH_NUM=CH_DIG
	# dash only valid at start of number
	CH_SNM=CH_NUM + CH_DSH

	CH_SEARCH_TABLE = [
		(lambda c: c.isalpha(), CH_ALP),
		(lambda c: c.isdigit(), CH_NUM),
		(lambda c: c.isspace(), CH_SPC),
		(lambda c: c == ':', 	CH_COL),
		(lambda c: c == '/', 	CH_SLS),
		(lambda c: c == '.', 	CH_DOT),
		(lambda c: c == '"', 	CH_QUT),
		(lambda c: c == ',', 	CH_COM),
		(lambda c: c == '!', 	CH_BNG),
		(lambda c: c == '-', 	CH_DSH),
		(lambda c: c == '>', 	CH_RAN),
		(lambda c: c == '<', 	CH_LAN),
		(lambda c: c == ']', 	CH_RSQ),
		(lambda c: c == '[', 	CH_LSQ),
		(lambda c: c == ')', 	CH_RPR),
		(lambda c: c == '(', 	CH_LPR),
		(lambda c: c == '@', 	CH_AAT),
		(lambda c: c == ';', 	CH_SCL),
		(lambda c: c == '=', 	CH_EQL),
		(lambda c: c == '+', 	CH_PLS),
		(lambda c: c == '_', 	CH_UND),
		(lambda c: c == '|', 	CH_SEP),
		(lambda c: c == chr(0),	CH_NIL),
		(lambda c: True, 	CH_OTH)]


	@classmethod
	def ch_in(_, child, parent):
		# test the child bits in the parent
		return all((parent >> j) & 1
			for j in filter(lambda x:x is not None,
				[i if ((child >> i) & 1) == 1
				   else None
                                   for i in range(int(log(child, 2)) + 1)]))

	def chartype(self, char):
		for pair in GamLine.CH_SEARCH_TABLE:
			rule = pair[0]
			_type = pair[1]
			if rule(char):
				return _type

	TK_TXT=1	# unquoted text (no spaces)
	TK_NUM=2	# number
	TK_FSP=3	# field seperator
	TK_RSP=4	# record seperator

	ALL_TOKENS = [TK_TXT, TK_NUM, TK_FSP, TK_RSP]
	
	@classmethod
	def find_tk_str(_, tk):
			return {
			GamLine.TK_TXT:  '[Token Text]',
			GamLine.TK_NUM:  '[Token Number]',
			GamLine.TK_FSP:  '[Token Field Sep]',
			GamLine.TK_RSP:  '[Token Record Sep]'
				}.get(tk,'[Token Unknown]')
	

	ST_STRT 	= 1<<1
	ST_TEXT		= 1<<2
	ST_QUOT		= 1<<3
	ST_NUMB		= 1<<4
	ST_NUMB		= 1<<4
	ST_ENQT		= 1<<5
	ST_OPER		= 1<<6

	ALL_STATES = [ST_STRT, ST_TEXT, ST_NUMB, ST_ENQT]

	def find_st_str(self, st):
		return {
			GamLine.ST_STRT: '[Lexx State Start]',
			GamLine.ST_TEXT: '[Lexx State Text]',
			GamLine.ST_QUOT: '[Lexx State Quote]',
			GamLine.ST_NUMB: '[Lexx State Number]',
			GamLine.ST_ENQT: '[Lexx State End Quote]',
			GamLine.ST_ENQT: '[Lexx State Operator]'
				}.get(st,'[Lexx State Unknown]')


	def LexxError(self, msg, st, st_str):
		raise GamLexxError(n=self.count, st=st, st_str=st_str, msg=msg)
	# main lex function
	def lex_line(self, line):
		idx=0
		arg_cnt=0
		def buff_default():
			return [None, '']
		
		self._lex_buff = buff_default()
		self._res=[]
		def buff_emit():
			#DP('buff emit %s' % str(self._lex_buff))
			if self._lex_buff[0] is not None:
				self._res.append(tuple(self._lex_buff))
			self._lex_buff = buff_default()

		def buff_set_tk(tk):
			#DP('buff set tk %s' % tk)
			self._lex_buff[0] = tk

		def buff_in(txt):
			#DP('buff in %s' % txt)
			self._lex_buff[1] += txt
			
		st=GamLine.ST_STRT

		typ=GamLine.CH_OTH
		in_quote=False
		dot_unseen=True

		line += GamLine.NULL
		i=0
		while i < len(line):
			typ = self.chartype(line[i])
			if typ == GamLine.CH_OTH:
				self.LexxError('invalid character "%s"' % line[i], st, self.find_st_str(st))
			if st == GamLine.ST_TEXT:
			# if not in a quote, end of alpha means end of word
				# special case: quote within string starts
				# new quoted text and saves word
				if typ == GamLine.CH_QUT:
					buff_emit()
				elif GamLine.ch_in(typ, GamLine.CH_TXT):
					buff_in(line[i])
				else: #typ not in GamLine.CH_TXT
					# append buff to result and wipe buff
					buff_emit()
					st=GamLine.ST_STRT
			elif st == GamLine.ST_QUOT:
				if typ == GamLine.CH_QUT:
					buff_emit()
					st=GamLine.ST_ENQT
				else:
					buff_in(line[i])
			elif st == GamLine.ST_NUMB:
				if GamLine.ch_in(typ, GamLine.CH_NUM):
					buff_in(line[i])
				# one decimal point per number
				elif dot_unseen and typ == GamLine.CH_DOT:
					buff_in(line[i])
					dot_unseen=False
				else:
					buff_emit()
					st=GamLine.ST_STRT
			elif st == GamLine.ST_STRT:
				pass
			else:
				self.LexxError('Unknown lexx state')

			if st == GamLine.ST_STRT:
				if GamLine.ch_in(typ, GamLine.CH_SNM):
					buff_emit()
					buff_set_tk(GamLine.TK_NUM)
					buff_in(line[i])
					dot_unseen=True
					st=GamLine.ST_NUMB
				elif GamLine.ch_in(typ, GamLine.CH_TXT):
					buff_emit()
					buff_set_tk(GamLine.TK_TXT)
					buff_in(line[i])
					st=GamLine.ST_TEXT
				elif typ == GamLine.CH_NIL:
					buff_emit()

			if st != GamLine.ST_QUOT and st != GamLine.ST_ENQT:
				if typ == GamLine.CH_COL:
					buff_emit()
					buff_set_tk(GamLine.TK_FSP)
					buff_in(':')
					st = GamLine.ST_STRT
				elif typ == GamLine.CH_SLS:
					buff_emit()
					buff_set_tk(GamLine.TK_RSP)
					buff_in('/')
					st = GamLine.ST_STRT
				elif typ == GamLine.CH_QUT:
					buff_emit()
					buff_set_tk(GamLine.TK_TXT)
					st=GamLine.ST_QUOT
			elif st == GamLine.ST_ENQT:
				st=GamLine.ST_STRT
			i += 1

		if st == GamLine.ST_QUOT:
			raise BadGamError('lex: umatched "')
		#elif st != GamLine.ST_STRT:
			#raise BadGamError('ended lex in state %s' % st)
		DP('lexed line %s' % str(self._res))
		DP('(orig): %s' % str(line))
		return self._res

	def __init__(self, line):
		self.count = GamLine.do_count()
		self.lexxed = self.lex_line(line)
		self.line = line

	def __bool__(self):
		return len(self.lexxed) > 0


	def __str__(self):
		return str(self.lexxed)

	def __iter__(self):
		yield from self.lexxed

	def __get__(self, index):
		return self.lexxed[index]


class GamEXEComm:
	def __init__(self, func, args, line):
		self.func = func
		self.args = args
		self.line = line

	def __call__(self, gs):
		output=''
		output += self.func(gs, self.args)
		DP('EXE %s' % str(self.line.line))

		return output

	def __str__(self):
		return str(self.line.line)

	def __repr__(self):
		return 'EXE(%s)' % repr(self.line.line)

def o3(a, b, c, sep='', pre=''):
	return '%s%s\t%s%s\t%s%s\n' % (pre, a, sep, b, sep, c)

def o2(a, b, sep='', pre=''):
	return '%s%s\t%s%s\n' % (pre, a, sep, b)
	

class GamParser:
	ST_NONE	= 1<<0
	ST_GAM	= 1<<1
	ST_ARG	= 1<<2
	ST_EOF	= 1<<3
	ST_APP	= 1<<4
	ST_DEL	= 1<<5
	ST_ADD	= 1<<6
	ALL_STATES = [ST_NONE, ST_GAM, ST_ARG, ST_EOF, ST_APP, ST_DEL, ST_ADD]

	def state(self):
		return self._state

	def set_st(self, st):
		if st in GamParser.ALL_STATES:
			DP('%s -> %s' % (self.state_str(), self.find_st_str(st)))
			self._state = st
			

	def find_st_str(self, st):
		return {
			GamParser.ST_NONE:'[Parse State None]',
			GamParser.ST_GAM: '[Parse State Gam]',
			GamParser.ST_ARG: '[Parse State Arg]',
			GamParser.ST_EOF: '[Parse State EOF]',
			GamParser.ST_APP: '[Parse State Append]',
			GamParser.ST_DEL: '[Parse State Delete]',
			GamParser.ST_ADD: '[Parse State Add]'
				}.get(st, '[Parse State Unknown]')

	def state_str(self):
		return self.find_st_str(self._state)

	def __init__(self):
		self._state = GamParser.ST_NONE

	def ParseError(self, i, msg, tbl=None):
		raise GamParseError(n=i, st=self.state(), \
			st_str=self.state_str(), msg=msg, tbl=tbl)

	ARG_PARSE_FMT="""Invalid argument:
\t\tAct:\t%s
\t\tWant:\t%s
\t\tGot:\t%s
%s"""
	def ArgParseError(self, i, act, want, got, opt=''):
		self.ParseError(i, msg=GamParser.ARG_PARSE_FMT % (act, want, got, opt))
	
	def parse(self, line, i):
		
		def _tk(n, a):
			if n > len(a) - 1:
				return None
			return a[n][0]

		def _vl(n, a):
			if n > len(a) - 1:
				return None
			return a[n][1]

		def args_txt_1(args, coersion=str, tn='str', opt=False):
			argc = len(args)
			ac = _vl(0, args)
			tk = _tk(1, args)
			vl = _vl(1, args)

			def validate_txt_1opt(E, argc, tk):
				if argc > 2:
					E('0 or 1 args', '%d args\n' % argc)
				elif argc == 2 and tk != GamLine.TK_TXT:
					E('1 string', 'expected text\n')

			def validate_txt_1nonopt(E, argc, tk):
				if argc != 2:
					E('1 arg', '%d args\n' % argc)
				elif tk != GamLine.TK_TXT:
					E('1 string', 'expected text\n')

			def E(want, msg):
				nonlocal vl
				got = str(vl)
				self.ArgParseError(i, ac, want, got, opt=msg)

			if opt:
				validate_txt_1opt(E, argc, tk)
				if argc == 1:
					return []
			else:
				validate_txt_1nonopt(E, argc, tk)

			try:
				return [(vl)]
			except (TypeError, ValueError):
				E(tn, 'cannnot coerce to %s\n' % tn)

		def args_num_1(args, coersion, tn, opt=False):
			argc = len(args)
			ac = _vl(0, args)
			tk = _tk(1, args)
			vl = _vl(1, args)

			def validate_num_1opt(E, argc, tk):
				if argc > 2:
					E('0 or 1 args', '%d args\n' % argc)
				elif argc == 2 and tk != GamLine.TK_NUM:
					E('1 number', 'expected number\n')

			def validate_num_1nonopt(E, argc, tk):
				if argc != 2:
					E('1 args', '%d args\n' % argc)
				elif tk != GamLine.TK_NUM:
					E('1 number', 'expected number\n')

			def E(want, msg):
				nonlocal vl
				got = str(vl)
				self.ArgParseError(i, ac, want, got, opt=msg)
			if opt:
				validate_num_1opt(E, argc, tk)
				if argc == 1:
					return []
			else:
				validate_num_1nonopt(E, argc, tk)

			try:
				return [coersion(vl)]
			except (TypeError, ValueError):
				E(tn, 'cannnot coerce to %s\n' % tn)

		def args_num_1opt(args, coersion, tn, opt=True):
			return args_num_1(args, coersion, tn, opt=True)

		def args_int_1opt(args):
			return args_num_1(args,
				lambda x: int(x), 'int', opt=True)

		def args_int_1(args):
			return args_num_1(args,
				lambda x: int(x), 'int', opt=False)

		def args_float_1opt(args):
			return args_num_1(args,
				lambda x: float(x), 'float', opt=True)

		def args_float_1(args):
			return args_num_1(args,
				lambda x: float(x), 'float', opt=False)

		def args_txt_or_num1(args):
			if len(args) > 1:
				args[1] = (GamLine.TK_TXT, str(args[1][1]))
			return args_txt_1(args)

		def args_gam(args):
			return args_float_1opt(args)

		def args_drop(args):
			return args_int_1opt(args)

		def args_warp(args):
			return args_int_1(args)

		def args_mag(args):
			return []

		def validate_gam_line(args):
			argc = len(args)
			ac = _vl(0, args)
			tk1= _tk(1, args)
			tk2= _tk(2, args)

			def E(want, got, msg):
				self.ArgParseError(i, ac, str(want), str(got), opt=msg)


			if argc > 1 and tk1 != GamLine.TK_TXT:
				E(GamLine.find_tk_str(GamLine.TK_TXT),
					GamLine.find_tk_str(tk2),
					'expected text')
			

		def args_const(args):
			argc = len(args)
			tk0= _tk(0, args)
			tk1= _tk(1, args)
			tk2= _tk(2, args)
			tk3= _tk(3, args)
			vl0= _vl(0, args)
			vl1= _vl(1, args)
			vl2= _vl(2, args)
			vl3= _vl(3, args)

			def E(want, got, msg):
				self.ArgParseError(i, vl0, want, got, opt=msg)
			if argc != 3:
				E('3 args', '%d args' % argc, 'bad arity')
			validate_gam_line(args)

			if tk3 != GamLine.TK_TXT and tk3 != GamLine.TK_NUM:
				E('text or number', GamLine.find_tk_str(tk3),
					'expected text or number')

			return [GamNam(E, vl0, vl1), GamValConst(E, vl2)]


		def args_poly(args):
			argc = len(args)
			tk0= _tk(0, args)
			tk1= _tk(1, args)
			tk2= _tk(2, args)
			tk3= _tk(3, args)
			vl0= _vl(0, args)
			vl1= _vl(1, args)
			vl2= _vl(2, args)
			vl3= _vl(3, args)

			def E(want, got, msg):
				self.ArgParseError(i, vl0, want, got, opt=msg)

			if argc < 3:
				E('3+ args', '%d args' % argc, 'bad arity')
			validate_gam_line(args)

			raw = ''.join([x[1] for x in args[2:]])
			return [GamNam(E, vl0, vl1), GamValPoly(E, raw)]

		
		def delta_gam(gs, args):
			if len(args) < 1:
				ts_dt = datetime.utcnow()
				# hack to get start time in save:
				gs.comms[gs.step_counter].line.line += \
					' ' + str(ts_dt.timestamp())
			else:
				ts_dt = ts_to_dt(args[0])
			gs.stack_push('GAM')
			gs.stack_push(ts_dt)
			return o2('GAM', ts_dt)

		def delta_app(gs, args):
			if gs.game is None:
				# history hack to remove failed add
				gs.comms[gs.step_counter].line.line = 'APPFAIL'
				return '%s\tno game loaded\n' % 'APP\n'

			gs.stack_push('APP')
			gs.stack_push(None) # keep pushing 2 things at once
			return o2('APP', 'now')

		def delta_del(gs, args):
			if gs.game is None:
				# history hack to remove failed del
				gs.comms[gs.step_counter].line.line = 'DELFAIL'
				return '%s\tno game loaded\n' % 'DEL\n'

			gs.stack_push('DEL')
			gs.stack_push(None) # keep pushing 2 things at once
			return o2('DEL', 'now')

		def delta_drop(gs, args):
			argc = len(args)
			e=''
			# include self in num to drop
			if argc == 0:
				gs.drop(gs.step_counter + 1)
				e='ALL'
			else:
				gs.drop(args[0] + 1)
				e=str(args[0])

			return o2('DROP', e)

		def delta_dump(gs, args):
			argc = len(args)
			e=''
			# don't include self in num to dump
			if argc == 0:
				o = '\n'.join(gs.history()) + '\n'
				e ='ALL'
			else:
				h = gs.history(n=gs.step_counter)
				o = '\n'.join(h) + '\n'
				e=str(args[0])
			output = o2('DUMP', e)
			output += o
			return output

		def delta_report(gs, args):
			argc = len(args)
			now = datetime.utcnow().timestamp()
			ts = args[0] if argc > 0 else now
			output = o2('REPORT', '%s' % dt_str(ts_to_dt(ts)))


			if argc == 0: # save for re-run of this report command
				gs.comms[gs.step_counter].line.line += ' ' + str(ts)
				# hack to get start time in save:
				#gs.comms[gs.step_counter].line.line += \
				#	' ' + str(ts_dt.timestamp())

			if gs.game is None:
				return '%s\tno game loaded\n' % output

			output += gs.report(ts)

			return output

		def delta_warp(gs, args):
			secs = float(args[0])
			gs.warp(secs)
			return o2('WARP', secs)

		def stack_pop_two(gs):
			if len(gs.stack) < 2:
				raise GamException(gs, 'stack underflow')
			return (gs.stack_pop(), gs.stack_pop())

		def delta_mag(gs, args):
			schema = []
			a, b = stack_pop_two(gs)
			while b != 'GAM':
				schema += [(b, a)]
				a, b = stack_pop_two(gs)
			try:
				gs.game = Gam(schema, a.timestamp())
				gs._warp = 0
			except BadGamError as e:
				raise GamException(gs, msg=str(e))
		
			return o2('START', a)

		def delta_ppa(gs, args):
			schema = []
			a, b = stack_pop_two(gs)
			i = 0
			while b != 'APP':
				schema += [(b, a)]
				a, b = stack_pop_two(gs)
				i += 1
			try:
				gs.game.append(schema)
			except BadGamError as e:
				raise GamException(gs, msg=str(e))
		
			return o2('APPENDED', i)

		def delta_trm(gs, args):
			#gs.stack_push()
			gs.stack_push(gs.sh)


		def delta_dda(gs, args):
			schema = []
			a, b = stack_pop_two(gs)
			#lhs = gs.game.schema.get(
			i=0
			while b != 'ADD':
				schema += [(b, a)]
				a, b = stack_pop_two(gs)
				i += 1
				if i > 2:
					raise GamException(gs, msg='too many things to add')



			try:
				gs.game.append(schema)
			except BadGamError as e:
				raise GamException(gs, msg=str(e))
		
			return o2('ADDED', i)

		def delta_led(gs, args):
			tis = []
			a, b = stack_pop_two(gs)
			while b != 'DEL':
				tis += [b]
				a, b = stack_pop_two(gs)
			i = 0
			for ti in tis:
				if gs.game.delete(ti):
					i += 1
		
			return o2('DELETED', i)

		def delta_runfail(gs, args):
			sh = args[0]
			return o2('RUNFAIL', sh)

		def delta_appfail(gs, args):
			return 'APPFAIL\n'

		def delta_delfail(gs, args):
			return 'DELFAIL\n'

		def delta_run(gs, args):
			sh = args[0]
			output = o2('SH', sh)
			output += gs.new_sh(sh)

			if gs.sh:
				gs.stack_push('SH')
				gs.stack_push(gs.sh)
			else:
				# history hack to remove failed load
				gs.comms[gs.step_counter].line.line = \
					'RUNFAIL "%s"' % sh 

			return output

		def delta_nur(gs, args):
			a, b = stack_pop_two(gs)
			args = []
			while b != 'SH':
				args = [str(a)] + args
				a, b = stack_pop_two(gs)
				
			output = o3('RUN', a, args)
			output += gs.do_run(a, args)
		
			return output

		def delta_arg(gs, args):
			arg = str(args[0])
			gs.stack_push(',')
			gs.stack_push(arg)
			return o2('ARG', '%s' % arg)

		def delta_gamdata(gs, args):
			gs.stack_push(args[0])
			gs.stack_push(args[1])
			#return 'SET\t%s\tTO\t %s\n' % (str(args[0]), str(args[1]))
			return o3(str(args[0]), 'TO',
				  str(args[1]), pre='SET\t')

		def delta_eof(gs, args):
			DP('entering EOF mode')
			gs.quiet = True
			return '\n--- plain text ---\n'

		def delta_foe(gs, args):
			DP('exiting EOF mode')
			gs.quiet = False
			return '---  end text  ---\n'

		def delta_echo(gs, args):
			return gs.comms[gs.step_counter].line.lexxed[0][1] + '\n' \
				if len(gs.comms[gs.step_counter].line.lexxed[0][1]) > 0 \
				else '\n'
		
		state_map = {
		# ACT 	 PROCESS ARGS		DELTA FUNC	STATE CHANGE
		GamParser.ST_NONE : { # STATE NONE: DEFAULT
		'GAM': 	 (args_float_1opt, 	delta_gam, 	GamParser.ST_GAM),
		'APP': 	 (lambda x:[],		delta_app, 	GamParser.ST_APP),
		'DEL':   (lambda x:[],		delta_del, 	GamParser.ST_DEL),
		'EOF': 	 (lambda x:[], 		delta_eof, 	GamParser.ST_EOF),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'RUN':   (args_txt_1,		delta_run, 	GamParser.ST_ARG),
		'RUNFAIL':(args_txt_1,		delta_runfail, 	None),
		'APPFAIL':(lambda x:[],		delta_appfail, 	None),
		'DELFAIL':(lambda x:[],		delta_delfail, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'REPORT':(args_float_1opt,	delta_report, 	None),
		'R':	(args_float_1opt,	delta_report, 	None),
		'WARP':	 (args_int_1,		delta_warp, 	None)},
		GamParser.ST_GAM : { # STATE GAM: GAM DATA ITEMS
		'GAM': 	 (lambda x:[],		delta_mag, 	GamParser.ST_NONE),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'CONST': (args_const,		delta_gamdata, 	None),
		'POLY':	 (args_poly,		delta_gamdata, 	None)},
		GamParser.ST_ARG : { # STATE ARG: ARGS FOR SH
		'RUN':   (lambda x:[],		delta_nur, 	GamParser.ST_NONE),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		',':	 (args_txt_or_num1,	delta_arg,	None)},
		GamParser.ST_EOF : { # STATE EOF: echo as plain text until EOF
		'EOF':   (lambda x:[],		delta_foe, 	GamParser.ST_NONE),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'*':     (lambda x:[],		delta_echo, 	None)},
		GamParser.ST_APP : { # STATE APP: append data to game
		'APP':   (lambda x:[],		delta_ppa, 	GamParser.ST_NONE),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'CONST': (args_const,		delta_gamdata, 	None),
		'POLY':	 (args_poly,		delta_gamdata, 	None)},
		GamParser.ST_DEL : { # STATE DEL: remove data from game
		'DEL':   (lambda x:[],		delta_led, 	GamParser.ST_NONE),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'CONST': (args_const,		delta_gamdata, 	None),
		'POLY':	 (args_poly,		delta_gamdata, 	None)}
		}

		# get map of valid acts for current state

		tbl = state_map.get(self.state(), None)
		if tbl:
			act = line.lexxed[0][1].upper()
			acts = tbl.get(act, None)
			#DP("table" + str(acts))
			# lookup $0 in table for parse state
			if acts is None:
				if self.state() != GamParser.ST_EOF:
					self.ParseError(i, 'Unknown act %s' % act, tbl=tbl)
				elif self.state() == GamParser.ST_EOF:
					# in EOF, echo  until EOF
					acts = tbl['*']

		else:
			raise BadGamError('unknown state %s\n' % self.state())

		# validate args using validator from table
		args = acts[0](line.lexxed)
		if acts[2]:
			self.set_st(acts[2])

		# success -- return callable executable command
		return GamEXEComm(acts[1], args, line)


def dt_str(dt):
	return dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
	
def ts_to_dt(ts):
	return datetime.fromtimestamp(ts)

class Gam:
	def __init__(self, schema, ts):
		# inut schema is list of (GamNam, GamVal) pairs
		# store internally indexed by str(nam)
		self.schema = {}
		self.append(schema)
		self.timestamp = ts
		DP('START GAME %s (on %s)' % (str(ts), self._started_str(ts)))

	def append(self, schema):
		for nam, val in schema:
			if str(nam) in self.schema.keys():
				raise BadGamError('name collision: "%s"' % str(nam))
			self.schema[str(nam)] = (nam, val)

	def delete(self, ti):
		DP('try delete %s' % str(ti))
		if ti is None:
			return False
		DP('search: %s' % str(self.schema))
		p = self.schema.get(str(ti), None)
		DP('found: %s' % str(p))
		if p is None:
			return False
		DP('delete %s' % str(ti))
		del self.schema[str(ti)]
		return True
		
			

	def t(self, t=None):
		return datetime.utcnow().timestamp() - self.timestamp \
			if t is None else t - self.timestamp

	def _started_str(self, ts):
		return dt_str(ts_to_dt(ts)) if ts is not None else None

	def started_str(self):
		return self._started_str(self.timestamp)

	def report(self, ts, warp=0):
		t = self.t(ts)
		t_w = self.t(ts + warp)

		t_str = '%.2f' % t
		t_w_str = '%.2f' % t_w
		w_str = '%.2f' % warp

		output  = o3('nam(f)', 'f(t+w)', 'f', 	pre='\t')
		output += o3('t+w', 	t_w_str, '', 	pre='\t')
		output += o3('t', 	t_str, '', 	pre='\t')
		output += o3('w', 	w_str, '', 	pre='\t')
		for k in self.schema:
			pair = self.schema[k]
			output += o3(k, str(pair[1].f(t_w)),
					str(pair[1]),   pre='\t')
		return output

	def __repr__(self):
		return repr({repr(k):repr(self.schema[k]) for k in self.schema})

	def __iter__(self):
		yield from schema

class GamSt:
	def __init__(self, user):
		self.user 		= user
		self.parser 		= GamParser()

		self.game 		= None
		self.sh			= None
		self.error 		= None
		self.valid 		= False
		self.quiet 		= False

		self.stack		= []
		self.comms 		= []
		self.step_counter 	= 0
		self._warp 		= 0
		self._drop		= 0

	def warp(self, n):
		self._warp += n

	def drop(self, n):
		self._drop += n

	# effective time is (game.t + warp)
	def t(self):
		if self.game is None:
			return 0
		return self.game.t() + self._warp

	def stack_empty(self):
		return len(self.stack) == 0

	def stack_push(self, x):
		self.stack = [x] + self.stack

	def stack_pop(self):
		if len(self.stack) == 0:
			return None
		x = self.stack[0]
		del self.stack[0]
		return x

	def invalidate(self):
		self.valid = False

	def find_sh(self, n):
		if n is None:
			return None
		for p in SH_PATH:
			sh = '%s/%s.sh' % (p, n)
			if os.path.isfile(sh):
				return sh

	def new_sh(self, n):
		sh = self.find_sh(n)
		if sh:
			self.sh = sh
			if self.in_last_comm():
				return 'found %s\n' % sh
			else:
				return ''
		return 'not found\n'

	def in_last_comm(self):
		return self.step_counter == len(self.comms) - 1

	def do_run(self, sh, args):
		output = ''
		if self.sh is None or sh != self.sh:
			output += '%s not loaded\n' % sh
			return output
			
		# only run in last command to not re-run on every load
		if self.in_last_comm():
			try:
				res = subprocess.run([self.sh] + args,
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE)
				if res.returncode == 0:
					output += str(res.stdout, 'UTF-8')
					self.comms[self.step_counter].line.line += \
						'\nEOF\n"%s"\nEOF\n' % \
						'"\n"'.join(output.strip().split('\n'))
				else:
					output += 'failed\n'
			except PermissionError as e:
				raise GamException(self, str(e))
		return output
		

	def run_step(self):
		comm = self.comms[self.step_counter]
		output=''
		DP('==[Step %03d]===========\n%s\n%s' % \
			(self.step_counter, comm.line,
		   '======================='))
		try:
			if self.quiet:
				output += comm(self)
			else:
				output += '[%d]\t%s' % (self.step_counter,
					# Now we actually run the step
					comm(self)
				)
			self.step_counter += 1
			# only incremented on success
		except GamException as e:
			output += '%s\n' % e.string()
			self.error = e

		DP(output)

		return output

	def is_valid(self):
		return self.error is None

	def history(self, n=0):
		d = self.step_counter - self._drop
		if n == 0:
			s = 0
		else:
			s = d - n
		return [c.line.line for c in self.comms[s:d]] 
	
	def report(self, ts):
		return self.game.report(ts, self._warp) if self.game is not None else None

	def has_comms(self):
		return len(self.comms) > self.step_counter
	
	def ready(self):
		return self.has_comms() and self.is_valid()

	def header(self):
		return 'INIT v%s\n' % VERSION


	def lexx_parse(self, l):
		n = len(self.comms)
		output = '(%d)\tPARSE\t%s\n' % (n, l)
		try:
			l = GamLine(l)
			if l:
				c = self.parser.parse(l, n)
				self.comms.append(c)
		except GamError as e:
			DP('GamError raised! str = [%s]' % str(e))
			output += str(e)
			self.error = e
		except Exception as e:
			output += 'exception: %s\n' % str(e)
			output += '(in parse)\n'
			tb = traceback.format_exc()
			output += '%s\n' % str(tb)
			self.error = e

		return output

def do_load(u, n, ls=None):
	with open(n, 'r') as f:
		return [l.strip() for l in f.readlines()]

def do_save(u, n, ls):
	with open(n, 'w') as f:
		for l in ls:
			print(l, file=f)

def attempt_fop(do, ls, u, m, f):
	n = 'saves/%s.save' % u
	try:
		return ('[%s %s]\n' % (m, n), do(u, n, ls=ls))
	except FileNotFoundError:
		return ('[%s %s]\n' % (f, n), [])

def attempt_load(u):
	ls  = attempt_fop(do_load, None, u,
		'LOAD from ', 'FAIL read from')
	#DP('DO LOAD : [%s]' % str(ls))
	return ls

def attempt_save(ls, u):
	#DP('DO SAVE: [%s]' % ls)
	return attempt_fop(do_save, ls, u,
		'SAVE to', 'FAIL write to')

def run_game(user_lines, user):
	gs = GamSt(user)

	output = gs.header()
	
	msg, saved_lines = attempt_load(user)
	output += msg
	input_lines = saved_lines + user_lines

	out_pre=''
	for l in input_lines:
		out_pre += gs.lexx_parse(l)
		if gs.error is not None:
			output += out_pre
			break

	while gs.ready():
		output += gs.run_step()
	
	if gs.is_valid():
		h = gs.history()
		db = 'History:\n%s\n' % str(h)
		DP(db)
		tmp, res = attempt_save(h, user)
		if res is not None:
			output += tmp

	return output

def process_req_body(req_body, user):

	# restore newlines (CRLF => '\') and spaces ('+' => ' ')
	with_lines = req_body[len("in="):] \
		.replace('%0D%0A','\n') \
		.replace('+', ' ') \
		.replace('%21', '!') \
		.replace('%22', '"') \
		.replace('%2C', ',') \
		.replace('%2F', '/') \
		.replace('%3A', ':') \
		.replace('%40', '@')
	#DP('input = {\n%s\n}' % with_lines)

	lines = with_lines.split('\n')
	if lines == ['']:
		#empty singleton means empty lines
		lines = []
	
	return run_game(lines, user)

def handle_terminal(env, SR):
	user = get_authorized_user(env)


	req_body_size = get_req_body_size(env)
	req_body = ''
	msgs = [('user', user), ('appver', appver())]


	if user not in AUTH_USERS:
		return generate_html('<h3>user %s unauthorized</h3>' % \
			user, msgs, env, SR)

	if is_post_req(env):
		req_body = html.escape(str(env['wsgi.input'].read(req_body_size), "UTF-8"))

	msgs += [('body', req_body)]
	base = TERMINAL_HTML % { 'output' : process_req_body(req_body, user) }


	return generate_html(base, msgs, env, SR)

def handle_US(env, SR):
	user = get_authorized_user(env)

	base = ("<marquee>Underground Software Home " + \
		"| Bitcoin price: %s " + \
		"| Litecoin price: %s " + \
		"| Ethereum price: %s " + \
		"| Dogecoin price: %s </marquee>") % \
		(generate_price(5), generate_price(3), generate_price(1), generate_price(2))

	msgs = [('user', user), ('appver', appver())]

	return generate_html(base, msgs, env, SR)


def handle_404(env, SR):
	user = get_authorized_user(env)
	msgs = messageblock([('user', user), ('appver', appver())])

	return notfound_html(prepend() +
		"<h1>HTTP ERROR 404: NOT FOUND</h1>" + msgs, SR)

def application(env, SR):
	return {'/US': handle_US, '/terminal':handle_terminal} \
		.get(env.get('PATH_INFO',''), handle_404)(env, SR)
