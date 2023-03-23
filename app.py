import random, html, sys, re, os
from urllib.parse import parse_qs
from datetime import datetime
import traceback

from config import PREPEND

VERSION="0.1"
APPLICATION="mars"

GAME_HTML="""
<form class="game_output" class="game_output">
	<label for="out">Output</label>
	<textarea id="game_output" class="game_output" name="out" readonly>%(output)s</textarea>
</form>
	<script type="text/javascript">
		var TA = document.getElementById('game_output')
		TA.scrollTop = TA.scrollHeight
	</script>
<br />

<div class="game_input">
<div class="fast_game_input"><form method="post" class="fast_game_input">
	<input type="text" class="fast_game_input" name="in" autofocus />
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

def generate_html(doc, msgs, env, SR):
	head = ''
	for n in PREPEND:
		with open(n, 'r') as f:
			head += f.read()

	page = head + doc + messageblock(msgs)

	return ok_html(page, SR)

def get_authorized_user(env):
	query_string = env.get("QUERY_STRING", "")
	queries = parse_qs(query_string)
	user = queries.get('user', None)
	if user is not None:
		user = user[0]
	else:
		return env.get('QUERY_STRING','default')
	return user

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
NUM_re		='[0-9]+\.?[0-9]*'
POLY_re		='(%s:%s\/?)+' 	% (NUM_re, NUM_re)
CONST_re 	='[_0-9a-zA-Z ]+'
VAL_re 		='(%s|%s)' 	% (POLY_re, CONST_re)
TYPE_IDENT_re	='%s:%s'	% (TYPE_re, IDENT_re)
GAME_re		='GAM.*'
DROP_re		='DROP\W*(%s)?' % (NUM_re)
DUMP_re		='DUMP.*'
MAG_re		='MAG.*'	
GAME_LINE_re	='%s %s'	% (TYPE_IDENT_re, VAL_re)
START_LINE_re	='START\W*(%s)?'% (NUM_re)
WARP_LINE_re	='WARP\W*(%s)?'	% (NUM_re)
REPORT_LINE_re	='REPORT.*'
COMM_ST_NONE_re	='(\W*|%s|%s|%s|%s|%s|%s)' % (GAME_re, START_LINE_re, WARP_LINE_re, REPORT_LINE_re, DROP_re, DUMP_re)
COMM_ST_GAM_re 	='(%s|%s)' % (GAME_LINE_re, MAG_re)
COMM_re		='(%s|%s)'	% (COMM_ST_NONE_re, COMM_ST_GAM_re)

def just(reg):
	return '^%s$' % reg

def assert_valid(rex, data):
	DP('GAM validate %s by regex %s' % (data, rex))
	if re.search(just(rex), data) is None:
		raise GamParseError(msg='data "%s" failed regex "%s"' % (data, rex))

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

	def __init__(self, msg='undefined parse error', n=-1, st=-1, st_str='?'):
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
	def __init__(self, typ, nam):
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
	def __init__(self, val):
		assert_valid(VAL_re, val)

class GamValPoly(GamVal):
	def __init__(self, val):
		super().__init__(val)
		assert_valid(POLY_re, val)
		
		DP(str(val))
		pairs_raw = val.split('/')
		self.pairs = [(float(pair[0]), float(pair[1])) \
			for pair in [pair_raw.split(':') \
				for pair_raw in pairs_raw]]

	def _str(self, fmt, sep):
		base = ''
		for p in self.pairs:
			base += fmt % (p[0], p[1], sep)

		# snip off terminating $sep
		base = base[:len(base)-len(sep)]

		return base

	def f(self, t):
		total=0
		for p in self.pairs:
			total += p[0] * (t ** p[1])
			DP('POLY TERM %g = %g * t ^ %g' % (total, p[0], p[1]))
		
		return '%g' % total

	def __str__(self):
		return 'f(t) = %s' % self._str('(%g)*t^(%g)%s', ' + ')

	def __repr__(self):
		return 'GamValPoly([%s])' % self._str('("%g","%g")%s', ',')

class GamValConst(GamVal):
	def __init__(self, val):
		super().__init__(val)
		assert_valid(CONST_re, val)
				
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
	CH_NUM=1<<2	# numeric character
	CH_SPC=1<<3	# whitespace character
	CH_COL=1<<4	# colon (:)
	CH_SLS=1<<5	# slash (/)
	CH_DOT=1<<6	# dot (.)
	CH_QUT=1<<7	# quote (")
	CH_DSH=1<<8	# dash (-)
	CH_NIL=1<<9	# GamLine.NULL
	def chartype(self, char):
		if char.isalpha():
			return GamLine.CH_ALP
		elif char.isdigit():
			return GamLine.CH_NUM
		elif char.isspace():
			return GamLine.CH_SPC
		elif char == ':':
			return GamLine.CH_COL
		elif char == '/':
			return GamLine.CH_SLS
		elif char == '.':
			return GamLine.CH_DOT
		elif char == '"':
			return GamLine.CH_QUT
		elif char == '-':
			return GamLine.CH_DSH
		elif char == GamLine.NULL:
			return GamLine.CH_NIL
		else:
			return GamLine.CH_OTH

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
	ST_ENQT		= 1<<5

	ALL_STATES = [ST_STRT, ST_TEXT, ST_NUMB, ST_ENQT]

	def find_st_str(self, st):
		return {
			GamLine.ST_STRT: '[Lexx State Start]',
			GamLine.ST_TEXT: '[Lexx State Text]',
			GamLine.ST_QUOT: '[Lexx State Quote]',
			GamLine.ST_NUMB: '[Lexx State Number]',
			GamLine.ST_ENQT: '[Lexx State End Quote]'
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
				elif typ == GamLine.CH_ALP:
					buff_in(line[i])
				else: #typ != GamLine.CH_ALP
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
				if typ == GamLine.CH_NUM:
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
				if typ == GamLine.CH_NUM or \
						typ == GamLine.CH_DSH:
					buff_emit()
					buff_set_tk(GamLine.TK_NUM)
					buff_in(line[i])
					dot_unseen=True
					st=GamLine.ST_NUMB
				elif typ == GamLine.CH_ALP:
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
		return self._res

	def __init__(self, line):
		self.count = GamLine.do_count()
		self.lexxed = self.lex_line(line)
		self.line = line
		# cut off '\n'?
		#self.line = line[:len(line)-1]

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
		DP('RUN %s' % str(self.line.line))

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
	ALL_STATES = [ST_NONE, ST_GAM]

	def state(self):
		return self._state

	def set_st(self, st):
		if st in GamParser.ALL_STATES:
			DP('%s -> %s' % (self.state_str(), self.find_st_str(st)))
			self._state = st
			

	def find_st_str(self, st):
		return {
			GamParser.ST_NONE:'[Parse State None]',
			GamParser.ST_GAM: '[Parse State Gam]'
				}.get(st, '[Parse State Unknown]')

	def state_str(self):
		return self.find_st_str(self._state)

	def __init__(self):
		self._state = GamParser.ST_NONE

	def ParseError(self, i, msg):
		raise GamParseError(n=i, st=self.state(), \
			st_str=self.state_str(), msg=msg)

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

			if argc > 1 and tk1 != GamLine.TK_FSP:
				E(GamLine.find_tk_str(GamLine.TK_FSP),
					GamLine.find_tk_str(tk1),
					'expected field separator (%s)'\
						 % ':')

			if argc > 2 and tk2 != GamLine.TK_TXT:
				E(GamLine.find_tk_str(GamLine.TK_TXT),
					GamLinefind_tk_str(tk2),
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
			if argc != 4:
				E('4 args', '%d args' % argc, 'bad arity')
			validate_gam_line(args)

			if tk3 != GamLine.TK_TXT and tk3 != GamLine.TK_NUM:
				E('text or number', GamLine.find_tk_str(tk3),
					'expected text or number')

			return [GamNam(vl0, vl2), GamValConst(vl3)]


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

			if argc < 4:
				E('4+ args', '%d args' % argc, 'bad arity')
			validate_gam_line(args)

			raw = ''.join([x[1] for x in args[3:]])
			return [GamNam(vl0, vl2), GamValPoly(raw)]

		
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

			if gs.game is None:
				return '%s\tno game loaded\n' % output

			if argc == 0: # save for re-run of this report command
				gs.comms[gs.step_counter].line.line += ' ' + str(ts)

			output += gs.report(ts)

			return output

		def delta_warp(gs, args):
			secs = float(args[0])
			gs.warp(secs)
			return o2('WARP', secs)

		def delta_mag(gs, args):
			schema = []
			a, b = gs.stack_pop(), gs.stack_pop()
			while b != 'GAM':
				if len(gs.stack) < 2:
					raise GamException(gs, 'stack underflow')
				
				schema += [(b, a)]

				a = gs.stack_pop()
				b = gs.stack_pop()
			try:
				gs.game = Gam(schema, a.timestamp())
			except BadGamError as e:
				raise GamException(gs, msg=str(e))
		
			return o2('MAG', a)
						
		def delta_gamdata(gs, args):
			gs.stack_push(args[0])
			gs.stack_push(args[1])
			#return 'SET\t%s\tTO\t %s\n' % (str(args[0]), str(args[1]))
			return o3(str(args[0]), 'TO',
				  str(args[1]), pre='SET\t')

		
		state_map = {
		# ACT 	 ARGS_VALID?		DELTA FUNC	STATE CHANGE
		GamParser.ST_NONE : {
		'GAM': 	 (args_float_1opt, 	delta_gam, 	GamParser.ST_GAM),
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'REPORT':(args_float_1opt,	delta_report, 	None),
		'WARP':	 (args_int_1,		delta_warp, 	None)},
		GamParser.ST_GAM : {
		'DROP':  (args_int_1opt,	delta_drop, 	None),
		'DUMP':  (args_int_1opt,	delta_dump, 	None),
		'MAG': 	 (lambda x:[],		delta_mag, 	GamParser.ST_NONE),
		'CONST': (args_const,		delta_gamdata, 	None),
		'POLY':	 (args_poly,		delta_gamdata, 	None)}
		}

		# get map of valid acts for current state
		tbl = state_map.get(self.state(), None)
		if tbl:
			act = line.lexxed[0][1].upper()
			acts = tbl.get(act, None)
			# lookup $0 in table for parse state
			if acts is None:
				self.ParseError(i, 'Unknown act %s' % act)

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
		for nam, val in schema:
			if str(nam) in self.schema.keys():
				raise BadGamError('name collision: "%s"' % str(nam))
			self.schema[str(nam)] = (nam, val)
		self.timestamp = ts
		DP('START GAME %s (on %s)' % (str(ts), self._started_str(ts)))

	def t(self, t=None):
		return datetime.utcnow().timestamp() - self.timestamp \
			if t is None else t - self.timestamp

	def _started_str(self, ts):
		return dt_str(ts_to_dt(ts)) if ts is not None else None

	def started_str(self):
		return self._started_str(self.timestamp)

	def report(self, ts, warp=0):
		t = self.t(ts + warp)
		_t = self.t(ts) # _t is no no warp

		t_str = '%.2f' % t
		_t_str = '%.2f' % _t

		output  = o3('nam(f)', 'f(t)', 	'f', 	pre='\t')
		output += o3('t', 	t_str, 	'', 	pre='\t')
		output += o3('_t', 	_t_str, '', 	pre='\t')
		for k in self.schema:
			pair = self.schema[k]
			output += o3(k, str(pair[1].f(t)),
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
		self.valid 		= False
		self.error 		= None

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


	def run_step(self):
		comm = self.comms[self.step_counter]
		output=''
		DP('==[Step %03d]===========\n%s\n%s' % \
			(self.step_counter, comm.line,
		   '======================='))
		try:
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
		return 'START GAME %s\n' % VERSION

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
	n = '%s.game' % u
	with open(n, 'r') as f:
		return [l.strip() for l in f.readlines()]

def do_save(u, n, ls):
	with open(n, 'w') as f:
		for l in ls:
			print(l, file=f)

def attempt_fop(do, ls, u, m, f):
	n = '%s.game' % u
	try:
		return ('[%s %s]\n' % (m, n), do(u, n, ls=ls))
	except FileNotFoundError:
		return ('[%s %s]\n' % (f, n), [])

def attempt_load(u):
	ls  = attempt_fop(do_load, None, u,
		'LOAD from ', 'FAIL read from')
	DP('DO LOAD : [%s]' % str(ls))
	return ls

def attempt_save(ls, u):
	DP('DO SAVE: [%s]' % ls)
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
		.replace('%3A', ':') \
		.replace('%2F', '/') \
		.replace('%22', '"')
	DP('input = {\n%s\n}' % with_lines)

	lines = with_lines.split('\n')
	if lines == ['']:
		#empty singleton means empty lines
		lines = []
	
	return run_game(lines, user)

def handle_game(env, SR):
	user = get_authorized_user(env)

	req_body_size = get_req_body_size(env)
	req_body = ''
	if is_post_req(env):
		req_body = html.escape(str(env['wsgi.input'].read(req_body_size), "UTF-8"))

	base = GAME_HTML % { 'output' : process_req_body(req_body, user) }

	msgs = [('user', user), ('appver', appver()), ('body', req_body)]

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
	return notfound_html("HTTP ERROR 404: NOT FOUND", SR)

def application(env, SR):
	return {'/US': handle_US, '/game':handle_game} \
		.get(env.get('PATH_INFO',''), handle_404)(env, SR)
