import os
import sys
import csv
import json

OUTPUT_FORMATS = ('csv', 'json', 'yara', )

def getHandler(output_format):
    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified.. using CSV")
        output_format = 'csv'

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class()

class OutputHandler(object):
    def print_match(self, fpath, page, name, match):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        print("[ERROR] %s" % (exception))

class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter = ',')
        self.csv_writer.writerow(('Indicator', 'Type', 'Campaign', 'Campaign Confidence', 'Confidence', 'Impact', 'Bucket List', 'Ticket', 'Action'))

    def print_match(self, match, ind_type, campaign, campaign_confidence, confidence, impact, tags):
        self.csv_writer.writerow((match, TYPE_CONVERSION[ind_type], campaign, campaign_confidence, confidence, impact, tags, "", ""))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((exception, 'error', 'error', 'low', 'low', 'low', 'error', 'error', 'error'))

class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match):
        data = {
            'path' : fpath,
            'file' : os.path.basename(fpath),
            'page' : page,
            'type' : name,
            'match': match
        }

        print(json.dumps(data))

    def print_error(self, fpath, exception):
        data = {
            'path'      : fpath,
            'file'      : os.path.basename(fpath),
            'type'      : 'error',
            'exception' : exception
        }

        print(json.dumps(data))

class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1
        
        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace('\\', '\\\\')
        print("\t\t%s = \"%s\"" % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = ' or '.join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")
