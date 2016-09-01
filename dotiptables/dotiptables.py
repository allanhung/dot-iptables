#!/usr/bin/python

import os
import errno
import sys
import re
import subprocess
import argparse
import pprint

import jinja2
from jinja2 import Template
from jinja2.loaders import PackageLoader

env = jinja2.Environment(
        loader=PackageLoader('dotiptables', 'templates'))

re_table='''^\*(?P<table>\S+)'''
re_table = re.compile(re_table)

re_chain='''^:(?P<chain>\S+) (?P<policy>\S+) (?P<counters>\S+)'''
re_chain = re.compile(re_chain)

re_rule='''^-A (?P<chain>\S+)( (?P<conditions>.*))?( -[jg] (?P<target>.*))'''
re_rule = re.compile(re_rule)

re_commit='''^COMMIT'''
re_commit=re.compile(re_commit)

re_comment='''^#(?P<comment>.*)'''
re_comment=re.compile(re_comment)

default_chain=['PREROUTING', 'POSTROUTING', 'INPUT', 'OUTPUT', 'FORWARD']

def is_final_target(target):
    return target.split()[0] in ['ACCEPT', 'DROP', 'REJECT', 'MASQUERADE', 'DNAT', 'SNAT', 'RETURN', 'MARK']

def process_rules(iptables, table, target_list, process_chain):
    flow_list=[]
    rule_condition={}
    while target_list:
        chain = target_list.pop(0)
        if chain not in process_chain:
            for i, cur_rule in enumerate(iptables[table][chain]['rules']):
                if cur_rule['chain'] not in rule_condition.keys():
                    rule_condition[cur_rule['chain']]={}
                rule_condition[cur_rule['chain']][i]=cur_rule['conditions']
                target_rule = cur_rule['target']  if is_final_target(cur_rule['target']) else cur_rule['target']+':name:w'
                flow_list.append([cur_rule['chain']+':R'+str(i)+':e',target_rule])
                if cur_rule['target'] not in target_list and not is_final_target(cur_rule['target']):
                    target_list.append(cur_rule['target'])
            process_chain.append(chain)
    if target_list:
        (tmpflow, tmprule, tmppro) = process_rules(iptables, table, target_list, process_chain)
        flow_list.extend(tmpflow)
        rule_condition.update(tmprule)
        process_chain.extend(tmppro)
    return flow_list, rule_condition, process_chain

def render_dot(output_file, iptables, table, chain):
    content_list = []
    content_list.append('/*')
    content_list.append(' * This represents the relationship between chains in the')
    content_list.append(' * {{table}} table.  To generate an SVG diagram from this')
    content_list.append(' * file, install GraphViz (http://www.graphviz.org/) and ')
    content_list.append(' * then run:')
    content_list.append(' *')
    content_list.append(' * dot -T svg -o %s.svg %s.dot' % ((table+'-'+chain), (table+'-'+chain)))
    content_list.append(' *')
    content_list.append(' */')
    content_list.append('digraph table_%s {' % (table+'_'+chain))
    content_list.append('  rankdir=LR;')
    content_list.append('')

    # add default policy to last rule
    if iptables[table][chain]['policy']:
        iptables[table][chain]['rules'].append({'conditions': '', 'target': iptables[table][chain]['policy'], 'chain': chain})
    (flow_list, rule_conditions, prochian) = process_rules(iptables, table, [chain], [])

    # add node
    result_list = []
    rule_list = []
    for rules in flow_list:
        for rule in rules:
            if is_final_target(rule):
                result_list.append(rule)
            else:
                ori_rule_name = rule.split(":")[0]
                if ori_rule_name not in rule_list:
                    table_context=[]
                    table_context.append('<<table border="0" cellborder="1" cellspacing="0"><tr><td bgcolor="lightgrey" PORT="name">%s</td></tr>' % ori_rule_name.ljust(int(len(ori_rule_name)*1.5)))
                    if ori_rule_name in rule_conditions.keys():
                        for k, v in rule_conditions[ori_rule_name].items():
                            table_context.append('<tr><td PORT="R%s">%s</td></tr>' % (str(k), v.ljust(int(len(v)*1.5))))
                    table_context.append('</table>>];')
                    content_list.append('  "%s" [URL="%s/%s.html",shape=none,margin=0,label=' % (ori_rule_name.replace('"','\\"'), table, ori_rule_name.replace('"','\\"'))+'\n'.join(table_context))
                    rule_list.append(ori_rule_name)
    content_list.append('')
    # add result node
    for rt in result_list:
        content_list.append('  "%s"' % rt)
    content_list.append('')

    # sorting
    content_list.append('{rank=same; "'+'" "'.join(result_list)+'"}')

    # add edge
    for flows in flow_list:
        (sflow_s, sflow_e) = flows[0].split(":",1)
        if is_final_target(flows[1]):
            content_list.append('"'+sflow_s+'":'+sflow_e+' -> "'+flows[1]+'"')
        else:
            (eflow_s, eflow_e) = flows[1].split(":",1)
            content_list.append('"'+sflow_s+'":'+sflow_e+' -> "'+eflow_s+'":'+eflow_e)
    content_list.append('}')
    with open(output_file, "wb") as f:
        f.write('\n'.join(content_list)+'\n')

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--outputdir', '-d', default='.')
    p.add_argument('--render', action='store_true')
    p.add_argument('input', nargs='?')

    return p.parse_args()

def stripped(fd):
    for line in fd:
        yield line.strip()

def handle_table(iptables, mo, line):
    iptables[mo.group('table')] = {}
    iptables['_table'] = iptables[mo.group('table')]

def handle_chain(iptables, mo, line):
    policy = mo.group('policy')
    if policy == '-':
        policy = None

    iptables['_table'][mo.group('chain')] = {
            'policy': policy,
            'rules': []
            }

def handle_rule(iptables, mo, line):
    fields = dict( (k, v if v else '') for k,v in mo.groupdict().items())
    iptables['_table'][fields['chain']]['rules'].append(fields)

def handle_commit(iptables, mo, line):
    iptables['_table'] = None

def read_chains(input):
    iptables = {
            '_table': None,
            }

    actions = (
            (re_table,   handle_table),
            (re_chain,   handle_chain),
            (re_rule,    handle_rule),
            (re_commit,  handle_commit),
            (re_comment, None),
            )

    for line in stripped(input):
        try:
            for pattern, action in actions:
                mo = pattern.match(line)
                if mo:
                    if action is not None:
                        action(iptables, mo, line)
                    raise StopIteration()
        except StopIteration:
            continue

        # We should never get here.
        print >>sys.stderr, 'unrecognized line:', line

    del iptables['_table']
    return iptables

def output_rules(iptables, opts):
    for table, chains in iptables.items():
        dir = os.path.join(opts.outputdir, table)
        try:
            os.mkdir(dir)
        except OSError, detail:
            if detail.errno == errno.EEXIST:
                pass
            else:
                raise
        for chain, data in chains.items():
            html_context=[]
            html_context.append('<?xml version="1.0" encoding="UTF-8"?>')
            html_context.append('<!DOCTYPE tml PUBLIC "-//W3C//DTD XHTML 1.1//EN"')
            html_context.append('"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">')
            html_context.append('<html xmlns="http://www.w3.org/1999/xhtml"')
            html_context.append('  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
            html_context.append('  xsi:schemaLocation="http://www.w3.org/MarkUp/SCHEMA/xhtml11.xsd"')
            html_context.append('  xml:lang="en">')
            html_context.append('  <head>')
            html_context.append('    <title>%s</title>' % chain)
            html_context.append('    <style>')
            html_context.append('    .builtin {')
            html_context.append('    color: red;')
            html_context.append('    }')
            html_context.append('    </style>')
            html_context.append('  </head>')
            html_context.append('  <body>')
            html_context.append('  <p>[ <A HREF="javascript:javascript:history.go(-1)">previous page</A> ]</p>')
            html_context.append('    <pre class="iptables">')
            for rule in data['rules']:
                if is_final_target(rule['target']):
                    html_context.append('-A %s %s -j <span class="builtin">%s</span>' % (rule['chain'], rule['conditions'], rule['target']))
                else:
                    html_context.append('-A %s %s -j <a href="%s.html">%s</a>' %(rule['chain'], rule['conditions'], rule['target'], rule['target']))
            if data['policy']:
                html_context.append('(default <span class="builtin">%s</span>)' % data['policy'])
            html_context.append('    </pre>')
            html_context.append('  </body>')
            html_context.append('</html>')
            with open(os.path.join(dir, '%s.html' % chain), 'w') as fd:
                fd.write('\n'.join(html_context)+'\n')

def output_dot_table(iptables, opts, table):
    tmpl = env.get_template('table.dot')

    with open(os.path.join(opts.outputdir, '%s.dot' % table), 'w') as fd:
        fd.write(tmpl.render(
            table=table,
            chains=iptables[table],
            ))
        fd.write('\n')

def output_dot_table_chain(iptables, opts, table, chain):
    render_dot(os.path.join(opts.outputdir, '%s.dot' % (table+'-'+chain)), iptables, table, chain)

def output_dot(iptables, opts):
    tmpl = env.get_template('index.html')
    tb_list=[]
    with open(os.path.join(opts.outputdir, 'index.html'), 'w') as fd:
        for chain in default_chain:
            for table in iptables.keys():
                if chain in iptables[table].keys():
                    output_dot_table_chain(iptables, opts, table, chain)
                    tb_list.append(table+'-'+chain)
        fd.write(tmpl.render(tables=tb_list))
    tmpl = env.get_template('index.dot')
    with open(os.path.join(opts.outputdir, 'index.dot'), 'w') as fd:
        fd.write(tmpl.render())
    p = subprocess.Popen(['dot', '-T', 'svg', '-o',
            os.path.join(opts.outputdir, '%s.svg' % 'index'),
            os.path.join(opts.outputdir, '%s.dot' % 'index')])
    p.communicate()

def render_svg(iptables, opts):
    for chain in default_chain:
        for table in iptables.keys():
            if chain in iptables[table].keys():
                p = subprocess.Popen(['dot', '-T', 'svg', '-o',
                        os.path.join(opts.outputdir, '%s.svg' % (table+'-'+chain)),
                        os.path.join(opts.outputdir, '%s.dot' % (table+'-'+chain))])
                p.communicate()

def main():
    opts = parse_args()

    if not os.path.isdir(opts.outputdir):
        print >>sys.stderr, (
                'ERROR: output directory %s does not exist.' %
                (opts.outputdir)
                )
        sys.exit(1)

    print 'Reading iptables data.'
    iptables = read_chains(sys.stdin)

    print 'Generating DOT output.'
    output_rules(iptables, opts)
    output_dot(iptables, opts)

    if opts.render:
        print 'Generating SVG output.'
        render_svg(iptables, opts)

if __name__ == '__main__':
        main()

