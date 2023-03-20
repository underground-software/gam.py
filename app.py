import random, html, sys, re, os
from urllib.parse import parse_qs
from datetime import datetime

KDLP_URLBASE='/var/www/html/kdlp.underground.software/'
VERSION="0.1"
APPLICATION="mars"

def DP(strg):
	print(strg, file=sys.stderr)

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

	with open(KDLP_URLBASE + 'header', 'r') as f:
		head += f.read()
	with open(KDLP_URLBASE + 'nav_us', 'r') as f:
		head += f.read()

	page = head + doc + messageblock(msgs)

	return ok_html(page, SR)

def get_authorized_user(env):
	query_string = env.get("QUERY_STRING", "")
	queries = parse_qs(query_string)
	user = queries.get('user', None)
	if user is not None:
		user = user[0]
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
IDENT_re	='[a-zA-Z]+'
NUM_re		='[0-9]+\.?[0-9]*'
POLY_re		='(%s:%s\/?)+' 	% (NUM_re, NUM_re)
CONST_re 	='[_0-9a-zA-Z]+'
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
		raise BadGamError('data "%s" failed regex "%s"' % (data, rex))

class BadGamWarning(Exception):
	pass

class BadGamError(Exception):
	pass


class GamNam:
	def __init__(self, data):
		assert_valid(TYPE_IDENT_re, data)

		[typ, nam] = data.split(':')
		self.nam = nam
		self.typ = typ

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
			for pair in [pair_raw.split('-') \
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
		
		return total

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

	NULL=chr(0)
	CH_OTH=1<<0	# character not included
	CH_ALP=1<<1	# alphabetic character (both cases)
	CH_NUM=1<<2	# numeric character
	CH_SPC=1<<3	# whitespace character
	CH_COL=1<<4	# colon (:)
	CH_SLS=1<<5	# slash (/)
	CH_DOT=1<<6	# dot (.)
	CH_QUT=1<<7	# quote (")
	CH_NIL=1<<8	# GamLine.NULL
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
		elif char == GamLine.NULL:
			return GamLine.CH_NIL
		else:
			return GamLine.CH_OTH

	TK_TXT=1	# unquoted text (no spaces)
	TK_NUM=2	# number
	TK_TYP=3	# type name
	TK_FSP=4	# field seperator
	TK_RSP=5	# record seperator
	TK_NWL=6	# newline

	# input format: 
	# INPUT := COMM | INPUT\nCOMM
	# COMM := GAME | START_LINE | WARP_LINE | REPORT_LINE | DUMP_LINE
	# GAME := "GAM"\nGAME_LINE "MAG"
	# TYPE_IDENT := TYPE:IDENT
	# GAME_LINE := TYPE_IDENT VAL\n | GAME_LINE TYPE:IDENT VAL\n
	# IDENT :=~ [a-zA-Z]+
	# TYPE := "poly" | "const"
	# POLY := NUM-NUM | NUM-NUM/POLY
	# CONST := [_0-9a-zA-Z]+
	# NUM ~= [1-9]?[0-9]*
	# VAL := POLY | CONST
	# START_LINE := START | START <unix_timestamp>
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
			

		ST_START=1
		ST_TEXT=2
		ST_QUOTE=3
		ST_NUM=4
		ST_ENDQT=5

		st=ST_START

		typ=GamLine.CH_OTH
		in_quote=False
		dot_unseen=True

		line += GamLine.NULL
		i=0
		while i < len(line):
			typ = self.chartype(line[i])
			DP('lex %d char "%s/%d" typ %d st %d' % (i, line[i], ord(line[i]), typ, st))
			if typ == GamLine.CH_OTH:
				raise BadGamError('lex: unknown character "%s"' % line[i])
			if st == ST_TEXT:
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
					st=ST_START
			elif st == ST_QUOTE:
				if typ == GamLine.CH_QUT:
					buff_emit()
					st=ST_ENDQT
				else:
					buff_in(line[i])
			elif st == ST_NUM:
				if typ == GamLine.CH_NUM:
					buff_in(line[i])
				# one decimal point per number
				elif dot_unseen and typ == GamLine.CH_DOT:
					buff_in(line[i])
					dot_unseen=False
				else:
					buff_emit()
					st=ST_START
			elif st == ST_START:
				pass
			else:
				raise BadGamError('lex: unknown state %d' % st)

			if st == ST_START:
				if typ == GamLine.CH_NUM:
					buff_emit()
					buff_set_tk(GamLine.TK_NUM)
					buff_in(line[i])
					dot_unseen=True
					st=ST_NUM
				elif typ == GamLine.CH_ALP:
					buff_emit()
					buff_set_tk(GamLine.TK_TXT)
					buff_in(line[i])
					st=ST_TEXT
				elif typ == GamLine.CH_NIL:
					buff_emit()

			if st != ST_QUOTE and st != ST_ENDQT:
				if typ == GamLine.CH_COL:
					buff_emit()
					buff_set_tk(GamLine.TK_FSP)
					buff_in(':')
					st = ST_START
				elif typ == GamLine.CH_SLS:
					buff_emit()
					buff_set_tk(GamLine.TK_RSP)
					buff_in('/')
					st = ST_START
				elif typ == GamLine.CH_QUT:
					buff_emit()
					buff_set_tk(GamLine.TK_TXT)
					st=ST_QUOTE
			elif st == ST_ENDQT:
				st=ST_START
			i += 1

		if st == ST_QUOTE:
			raise BadGamError('lex: umatched "')
		#elif st != ST_START:
			#raise BadGamError('ended lex in state %s' % st)
		DP('lexed line %s' % str(self._res))
		return self._res

	def __init__(self, line):
		self.line = line
		self.lexxed = self.lex_line(self.line)
		self.lexxed.append((GamLine.TK_NWL, '\n'))


	def __str__(self):
		return str(self.lexxed)


class GamParser:
	ST_NONE	=1<<0
	ST_GAM	=1<<1
	def parse_st_str(self, st):
		return {
			GamParser.ST_NONE : 'none',
			GamParser.ST_GAM : 'gam'
		}[st]

	def __init__(self):
		self.lines = []
		
	def parse(self, line):
		pass

	def addline(self, line):
		self.lines = self.parse(line)
	

# contents should be a list of GAME_LINE items
class Gam:
	def __init__(self, contents, user):
		self.user = user
		self.stamps = []
		self.schema = {}
		for c in contents:
			assert_valid(GAME_LINE_re, c)

			[a,b] = c.split(' ', 1)
			i = GamNam(a)
			d = { 
				'poly' : GamValPoly,
				'const' : GamValConst
			}[i.typ](b)
			self.schema[str(i)] = (i,d)

	def timestamp(self):
		return self.stamps[-1] if len(self.stamps) > 0 else None

	def start(self, val):
		DP('START GAME %s (on %s)' % (str(val), self._started_str(val)))
		self.stamps.append(val)

	def get_t(self):
		return datetime.utcnow().timestamp() - self.timestamp()

	def _started_str(self, timestamp):
		return datetime.fromtimestamp(timestamp) \
			.strftime('%a, %d %b %Y %H:%M:%S GMT') \
			if timestamp is not None else None

	def started_str(self):
		return self._started_str(self.timestamp())

	def __str__(self):
		base='NEW GAME %s\n' % self.user
		for k in self.schema:
			(nam, val) = self.schema[k]
			base +='\t%s %s\n' % (str(nam), str(val))
		RE=''
		for stamp in self.stamps[::-1]:
			base +='%sSTART GAME\t%f (on %s)\n' % \
				(RE, self.timestamp(), self._started_str(stamp))
			RE='RE'
		return base

	def __repr__(self):
		return repr({repr(k):repr(self.schema[k]) for k in self.schema})

class GamSt:
	def set_parse_st(self, st):
		DP('parse state [%s -> %s]' % (self.parse_st_str(self.parse_st), self.parse_st_str(st)))
		self.parse_st = st
		self.parse_bf[self.parse_st] = []

	def get_parse_bf(self):
		return self.parse_bf[self.parse_st]

	def append_parse_bf(self, item):
		self.parse_bf[self.parse_st].append(item)

	def loaded(self):
		return self.game is not None

	def started(self):
		return self.loaded() and self.game.timestamp() is not None

	ST_NONE	=1<<0
	ST_GAM	=1<<1
	def parse_st_str(self, st):
		return {
			GamSt.ST_NONE : 'none',
			GamSt.ST_GAM : 'gam'
		}[st]


	def __init__(self, lines, user):
		self.valid = True
		self.input_buffer = lines
		self.history = []
		self.user = user
		self.game = None

		self.step_counter = 0
		self.parse_st = GamSt.ST_NONE
		self.parse_bf = {}

	def comm_check(self, comm, regex, loaded=True):
		if loaded and not self.loaded():
			raise BadGamWarning('game not loaded')
		assert_valid(regex, comm)
			
	def dispatch_game(self, comm):
		self.set_parse_st(GamSt.ST_GAM)
		return (True, 'start GAM block')

	def attempt_load(self):
		name = '%s.game' % self.user
		header = 'LOAD'
		try:
			with open(name, 'r') as f:
				self.input_buffer = f.read().splitlines() \
					+ self.input_buffer
			return '%s from %s\n' % (header, name)
		except:
			# there is prbably just no saved file
			return '%s failed for %s\n' % (header, name)

	def attempt_save(self):
		name = '%s.game' % self.user
		header = 'SAVE'
		try:
			with open(name, 'w') as f:
				for line in self.history:
					print(line, file=f)
			return '%s to %s' % (header, name)
		except:
			return '%s failed for %s\n' % (header, name)

	
	def dispatch_drop(self, comm):
		name = '%s.game' % self.user

		if len(comm) > 1:
			try:
				num = int(comm[1])
			except ValueError:
				num = 0
		else:
			num = 0

		i=0
		while i < num and i < len(self.history):
			del self.history[i]
		self.attempt_save()
		return (True, 'delete %d items from history' % num)
			
		

	def dispatch_dump(self, comm):
		return (True, '%s.game dump:\n%s' % (self.user, '\n'.join(self.history)))

	REPORT_FORM="""REPORT:
\tt=%(t)s
"""

	def dispatch_report(self, comm):

		message = GamSt.REPORT_FORM % { 't' : self.game.get_t() }

		for k in self.game.schema:
			p = self.game.schema[k]
			message += '\t%s=%s\n' % (str(nam), str(p[1]))

		return (True, message)

	def dispatch_warp(self, comm):
		if len(comm) > 1:
			try:
				time = int(comm[1])
			except ValueError:
				time = 0
		else:
			time = 0
		self.game.start(self.game.timestamp() - time)
		return (True, 'game warped %d seconds' % time)	

	def dispatch_default(self, comm):
		return (False, 'default dispatch called for comm %s' % comm)

	def newgame(self, gam):
		self.game = gam
		self.game.start(datetime.utcnow().timestamp())
		
	def dispatch_st_none(self, line):
		assert_valid(COMM_ST_NONE_re, line)
		# all top level commands start with X and a space for now
		comm = line.split(' ')
		dispatch = {
			# COMM		HANDLER		VALIDATION	MUST BE PLAYING
			'GAM': 	 (self.dispatch_game, 	GAME_re, 	False),
			'DROP':  (self.dispatch_drop, 	DROP_re, 	False),
			'DUMP':  (self.dispatch_dump, 	DUMP_re, 	True),
			'REPORT':(self.dispatch_report, REPORT_LINE_re, True),
			'WARP':	 (self.dispatch_warp, 	WARP_LINE_re, 	True),
		}.get(comm[0].upper(), (self.dispatch_default, '.*',	False))

		self.comm_check(line, dispatch[1], loaded=dispatch[2])
		return dispatch[0](comm)
				
	def dispatch_st_gam(self, line):
		assert_valid(COMM_ST_GAM_re, line)
		if re.search(MAG_re, line) is None:
			self.append_parse_bf(line)
			return (True, 'add "%s" to ST_GAM buffer' % line)
		self.set_parse_st(GamSt.ST_NONE)
		try:
			self.newgame(Gam(self.get_parse_bf(), self.user))
			return (True, 'new game started for user "%s"' % self.user)
		except BadGamWarning as e:
			return (True, 'newgame() warn: %s' % str(e))
		except Exception as e:
			return (False, 'newgame() error: %s' % str(e))

	def dispatch_input_line(self, line):
		assert_valid(COMM_re, line)
		if self.parse_st == GamSt.ST_NONE:
			return self.dispatch_st_none(line)
		elif self.parse_st == GamSt.ST_GAM:
			return self.dispatch_st_gam(line)
		else:
			return (False, 'mysterious parse state')

	def invalidate(self):
		self.valid = False

	def is_valid(self):
		return self.valid

	def run_step(self):
		next_line = self.input_buffer[0]
		try:
			# lex next line
			line = GamLine(next_line)
			#(success, message) = self.dispatch_input_line(line)
			(success, message) = (len(line.lexxed) > 1, str(line.lexxed))
		except BadGamWarning as e:
			line = None
			(success, message) = (True, 'run_step() warning: %s' % str(e))
		except Exception as e:
			line = None
			(success, message) = (False, 'run_step() error: %s' % str(e))
			self.invalidate()

		# include newline added
		if line and len(line.lexxed) < 2:
			# skip empty lines
			output = '# skip empty line\n'
		else:
			output='[%d] RUN %s\n' % (self.step_counter, next_line)
			self.step_counter += 1
		
		output += message + '\n'
		DP(output)

		
		if success:
			self.history.append(next_line)
			if line.lexxed[0][1] == 'DROP':
				DP('in DROP!')
				self.dispatch_drop(['DROP', '100'])
			
		del self.input_buffer[0]
		return output

	def has_input(self):
		return len(self.input_buffer) > 0
	
	def ready(self):
		return self.has_input() and self.is_valid()

def run_game(input_lines, user):
	game_state = GamSt(input_lines, user)

	output = game_state.attempt_load()
	while game_state.ready():
		output += game_state.run_step()
	output += game_state.attempt_save()

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



	base = """
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
<form method="post" class="fast_game_input"> <div class="fast_game_input">
	<label for="in">Fast Input</label>
	<input type="text" class="fast_game_input" name="in" autofocus />
	<br />
	<button type="submit">Submit</button>
</div></form>
<form method="post" class="multi_game_input"> <div class="multi_game_input">
	<label for="in">Input</label>
	<textarea class="multi_game_input" name="in"></textarea>
	<br />
	<button type="submit">Submit</button>
</div></form>
</div>
""" % { 'output' : process_req_body(req_body, user) }


	msgs = [('user', user), ('version', APPLICATION + " " + VERSION), ('body', req_body)]

	return generate_html(base, msgs, env, SR)

def handle_US(env, SR):
	user = get_authorized_user(env)

	base = \
		("<marquee>Underground Software Home " + \
		"| Bitcoin price: %s " + \
		"| Litecoin price: %s " + \
		"| Ethereum price: %s " + \
		"| Dogecoin price: %s </marquee>") % \
		(generate_price(5), generate_price(3), generate_price(1), generate_price(2))

	msgs = [('user', user), ('version', APPLICATION + " " + VERSION)]

	return generate_html(base, msgs, env, SR)


def handle_404(env, SR):
	return notfound_html("HTTP ERROR 404: NOT FOUND", SR)

def application(env, SR):
	return {'/US': handle_US, '/game':handle_game} \
		.get(env.get('PATH_INFO',''), handle_404)(env, SR)
