"""Independent, test-only recognizer for finite acyclic GBNF from the CLI.

This parses the actual GBNF text and expands it to Python Unicode regexes.
It never reads a JSON schema or calls converter/preflight implementation code.
It is not used in production and is not a substitute for geniex-proc Grammar.
"""
import json
import re

class Recognizer:
    def __init__(self, grammar):
        if isinstance(grammar, bytes):
            grammar = grammar.decode("utf-8", "strict")
        self.rules = {}
        for line in grammar.splitlines():
            if not line.strip():
                continue
            name, separator, expression = line.partition("::=")
            name = name.strip()
            if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name) or name in self.rules:
                raise ValueError("invalid/duplicate GBNF rule")
            tokens = self.lex(expression)
            ast, position = self.alternatives(tokens, 0)
            if position != len(tokens):
                raise ValueError("unconsumed GBNF")
            self.rules[name] = ast
        self.cache = {}
        self.regex = re.compile(self.expand(("ref", "root"), set()))

    @staticmethod
    def lex(text):
        out, pos = [], 0
        while pos < len(text):
            char = text[pos]
            if char.isspace():
                pos += 1
                continue
            if char == '"':
                end = pos + 1
                while end < len(text):
                    if text[end] == "\\":
                        end += 2
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
                else:
                    raise ValueError("unterminated GBNF literal")
                out.append(("lit", json.loads(text[pos:end])))
                pos = end
            elif char == "[":
                end = pos + 1
                while end < len(text):
                    if text[end] == "\\":
                        end += 2
                    elif text[end] == "]":
                        end += 1
                        break
                    else:
                        end += 1
                else:
                    raise ValueError("unterminated GBNF character class")
                value = text[pos:end]
                re.compile(value)
                out.append(("class", value))
                pos = end
            elif char in "()|?*+":
                out.append(char)
                pos += 1
            elif char == "{":
                match = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", text[pos:])
                if not match:
                    raise ValueError("invalid repetition")
                out.append(("repeat", match.group()))
                pos += len(match.group())
            else:
                match = re.match(r"[A-Za-z][A-Za-z0-9-]*", text[pos:])
                if not match:
                    raise ValueError("unrecognized GBNF token")
                out.append(("ref", match.group()))
                pos += len(match.group())
        return out

    @classmethod
    def alternatives(cls, tokens, position):
        choices = []
        while True:
            values = []
            while position < len(tokens) and tokens[position] not in ("|", ")"):
                item = tokens[position]
                if item == "(":
                    node, position = cls.alternatives(tokens, position + 1)
                    if position >= len(tokens) or tokens[position] != ")":
                        raise ValueError("unclosed group")
                    position += 1
                else:
                    if not isinstance(item, tuple) or item[0] == "repeat":
                        raise ValueError("missing repeat operand")
                    node, position = item, position + 1
                if position < len(tokens):
                    quantifier = tokens[position]
                    if quantifier in ("?", "*", "+"):
                        node, position = ("quant", node, quantifier), position + 1
                    elif isinstance(quantifier, tuple) and quantifier[0] == "repeat":
                        node, position = ("quant", node, quantifier[1]), position + 1
                values.append(node)
            choices.append(("seq", values))
            if position == len(tokens) or tokens[position] != "|":
                break
            position += 1
        return ("alt", choices), position

    def expand(self, node, active):
        kind = node[0]
        if kind == "lit":
            return re.escape(node[1])
        if kind == "class":
            return node[1]
        if kind == "seq":
            return "".join(self.expand(item, active) for item in node[1])
        if kind == "alt":
            return "(?:" + "|".join(self.expand(item, active) for item in node[1]) + ")"
        if kind == "quant":
            return "(?:" + self.expand(node[1], active) + ")" + node[2]
        if kind == "ref":
            name = node[1]
            if name in self.cache:
                return self.cache[name]
            if name in active or name not in self.rules or len(active) >= 128:
                raise ValueError("unknown/cyclic/deep GBNF reference")
            result = "(?:" + self.expand(self.rules[name], active | {name}) + ")"
            if len(result) > 2 * 1024 * 1024:
                raise ValueError("test expansion exceeds bound")
            self.cache[name] = result
            return result
        raise ValueError("unknown test AST")

    def accepts(self, text):
        if isinstance(text, bytes):
            text = text.decode("utf-8", "strict")
        return self.regex.fullmatch(text) is not None
