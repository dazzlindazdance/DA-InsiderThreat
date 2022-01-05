"""
Copyright (C) 2005-2021 Splunk Inc. All Rights Reserved.
"""
import csv
import importlib.util
import json
import logging
import re

from copy import deepcopy
from io import StringIO
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import normalizeBoolean

cexe_path = make_splunkhome_path(
    ['etc', 'apps', 'SA-Utils', 'lib', 'SolnCommon', 'cexe.py'])
cexe_spec = importlib.util.spec_from_file_location('SolnCommon.cexe', cexe_path)
cexe_module = importlib.util.module_from_spec(cexe_spec)
cexe_spec.loader.exec_module(cexe_module)
BaseChunkHandler = cexe_module.BaseChunkHandler
ArgumentError = cexe_module.ArgumentError

expandtoken_path = make_splunkhome_path(
    ['etc', 'apps', 'SA-Utils', 'bin', 'expandtoken.py'])
expandtoken_spec = importlib.util.spec_from_file_location('expandtoken', expandtoken_path)
expandtoken_module = importlib.util.module_from_spec(expandtoken_spec)
expandtoken_spec.loader.exec_module(expandtoken_module)
TokenExpander = expandtoken_module.TokenExpander

modaction_path = make_splunkhome_path(
    ["etc", "apps", "Splunk_SA_CIM", "lib", "cim_actions.py"])
modaction_spec = importlib.util.spec_from_file_location(
    'cim_actions',
    modaction_path)
modaction_module = importlib.util.module_from_spec(modaction_spec)
modaction_spec.loader.exec_module(modaction_module)
ModularAction = modaction_module.ModularAction
ModularActionTimer = modaction_module.ModularActionTimer
logger = ModularAction.setup_logger('risk_modalert')


class RiskModularAction(ModularAction):

    def __init__(self, settings, logger, action_name='risk'):
        super().__init__(settings, logger, action_name)

        # add status info
        self.addinfo()
        # search_name
        self.search_name = self.search_name or 'AdHoc Risk Score'
        # _risk
        self._risk = []
        self.threat_object_definitions = []
        # default risk score
        self.default_risk_score = 1.0

    def validate(self):
        if 'risk' in self.configuration:
            try:
                config_risk = json.loads(self.configuration['risk'])
                # verify config_risk is a list...
                if isinstance(config_risk, list):
                    # of dicts...
                    self._risk = [x for x in config_risk if isinstance(x, dict)]
                    # log number of discarded entries
                    if len(self._risk) != len(config_risk):
                        discarded_count = len(config_risk) - len(self._risk)
                        self.logger.warning('Discarded %s risk object definitions', discarded_count)
                else:
                    self.logger.warning('Invalid specification for risk parameter (must be a list).  See alert_actions.conf.spec')
            except Exception:
                self.logger.warning('Invalid specification for risk parameter (must be valid JSON). See alert_actions.conf.spec')

        # this creates a consistent fallback for discarded risk-json
        # and the specification of the risk_object_field/object_type/score triple
        if not self._risk:
            self._risk = [{
                "risk_object_field": self.configuration.get('risk_object_field'),
                "risk_object_type": self.configuration.get('risk_object_type'),
                "risk_score": self.configuration.get('risk_score')
            }]

        # pull out threat objects
        for risk_object_definition in self._risk:
            if 'threat_object_field' in risk_object_definition and 'threat_object_type' in risk_object_definition:
                self.threat_object_definitions.append({
                    'threat_object_field': risk_object_definition['threat_object_field'],
                    'threat_object_type': risk_object_definition['threat_object_type']
                })

    def get_threat_objects(self, result):
        threat_objects = []
        threat_object_types = []
        # 1-to-many relationship between risk objects and threat objects
        for threat_object_definition in self.threat_object_definitions:
            threat_object_field = threat_object_definition.get('threat_object_field')
            threat_object_type = threat_object_definition.get('threat_object_type')

            curr_threat_objects = []
            curr_threat_object_types = []

            if result.get(f'__mv_{threat_object_field}'):
                curr_threat_objects = modaction_module.parse_mv(result[f'__mv_{threat_object_field}'])
                curr_threat_object_types = [threat_object_type for t_obj in curr_threat_objects]
            elif result.get(threat_object_field):
                curr_threat_objects = [result[threat_object_field]]
                curr_threat_object_types = [threat_object_type]
            else:
                self.logger.warning("Specified threat_object_field '%s' does not exist in result.", threat_object_field)

            # add to total
            threat_objects.extend(curr_threat_objects)
            threat_object_types.extend(curr_threat_object_types)

        return threat_objects, threat_object_types

    def dowork(self, result):
        threat_objects, threat_object_types = self.get_threat_objects(result)

        # for each risk object definition
        for risk_object_definition in self._risk:
            # risk object field
            if result.get('__mv_risk_object') or result.get('risk_object'):
                self.logger.debug('Detected risk_object field in result; using.')
                risk_object_field = 'risk_object'
            elif risk_object_definition.get('risk_object_field'):
                self.logger.debug('Detected risk_object_field in definition; using.')
                risk_object_field = risk_object_definition['risk_object_field']
            else:
                self.logger.warning('risk_object_field could not be determined; skipping.')
                continue

            # process __mv_{risk_object_field}
            if result.get(f'__mv_{risk_object_field}'):
                risk_objects = modaction_module.parse_mv(result[f'__mv_{risk_object_field}'])
            # process {risk_object_field}
            elif result.get(risk_object_field):
                risk_objects = [result[risk_object_field]]
            else:
                self.logger.warning('risk_objects could not be determined; skipping.')
                continue

            # for each risk object
            for risk_object in risk_objects:
                risk_result = result.copy()
                risk_result['risk_object'] = risk_object

                # risk_object_type
                if risk_result.get('risk_object_type'):
                    self.logger.debug('Detected risk_object_type field in result; using.')
                elif risk_object_definition.get('risk_object_type'):
                    self.logger.debug('Detected risk_object_type in definition; using.')
                    risk_result['risk_object_type'] = risk_object_definition['risk_object_type']
                else:
                    self.logger.warning('risk_object_type could not be determined; skipping.')
                    continue

                # risk_score
                if 'risk_score' in risk_result:
                    self.logger.debug('Detected risk_score field in result; using.')
                    risk_score = risk_result['risk_score']
                elif risk_object_definition.get('risk_score'):
                    self.logger.debug('Detected risk_score in definition; using.')
                    risk_score = risk_object_definition['risk_score']
                else:
                    self.logger.warning(
                        'risk_score could not be determined; defaulting to (%s)',
                        self.default_risk_score
                    )
                    risk_score = self.default_risk_score

                try:
                    risk_score = float(risk_score)
                except Exception:
                    self.logger.warning(
                        'risk_score (%s) is invalid; defaulting to (%s)',
                        risk_score,
                        self.default_risk_score
                    )
                    risk_score = self.default_risk_score

                risk_result['risk_score'] = risk_score

                # threat_object
                if risk_result.get('__mv_threat_object') or risk_result.get('threat_object'):
                    self.logger.debug('Detected threat_object field in result; using.')
                elif len(threat_objects) > 1:
                    risk_result['__mv_threat_object'] = modaction_module.encode_mv(threat_objects)
                    self.logger.debug('Using threat_object from definition.')
                elif len(threat_objects) == 1:
                    risk_result['threat_object'] = threat_objects[0]
                    self.logger.debug('Using threat_object from definition.')
                else:
                    self.logger.warning('threat_object could not be determined; skipping.')

                # threat_object_type
                if risk_result.get('__mv_threat_object_type') or risk_result.get('threat_object_type'):
                    self.logger.debug('Detected threat_object_type field in result; using.')
                elif len(threat_object_types) > 1:
                    self.logger.debug('Using threat_object_type from definition.')
                    risk_result['__mv_threat_object_type'] = modaction_module.encode_mv(threat_object_types)
                elif len(threat_object_types) == 1:
                    self.logger.debug('Using threat_object_type from definition.')
                    risk_result['threat_object_type'] = threat_object_types[0]
                else:
                    self.logger.warning('threat_object_type could not be determined; skipping.')

                # risk_message
                field_risk_message, mvfield_risk_message = 'risk_message', '__mv_risk_message'
                if risk_result.get(mvfield_risk_message):
                    vals = [v for v in modaction_module.parse_mv(risk_result[mvfield_risk_message]) if v != '']
                    newvals = [TokenExpander.expand_tokens(x, risk_result) for x in vals]
                    risk_result[field_risk_message] = '\n'.join(newvals)
                    risk_result[mvfield_risk_message] = modaction_module.encode_mv(newvals)
                elif risk_result.get(field_risk_message):
                    risk_result[field_risk_message] = TokenExpander.expand_tokens(risk_result[field_risk_message], risk_result)
                elif self.configuration.get(field_risk_message):
                    self.logger.debug('Detected risk_message field in definition; using.')
                    risk_result[field_risk_message] = TokenExpander.expand_tokens(self.configuration[field_risk_message], risk_result)

                self.addevent(self.result2stash(risk_result, addinfo=True), 'stash')


class CollectRiskHandler(BaseChunkHandler):
    VALID_ARGS_RE = re.compile('^(search_name|risk|risk_message|risk_object_field|risk_object_type|risk_score|index|verbose)=(.+)$')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.modaction = None

    def handle_getinfo(self, metadata=None, data=None):
        metadata = {} if metadata is None else metadata

        searchinfo = metadata.get('searchinfo', {})
        session_key = searchinfo.get('session_key')

        # splunk calls this method twice. once for parsing,
        # once for actual execution. in parsing phase session_key
        # is not passed to this command. search/parser gathers
        # semantic map of commands, so it's necessary to return these things.
        if not session_key:
            return {
                'type': 'reporting',
                'required_fields': ['*', '_*']
            }

        # create modalert-style object
        settings = deepcopy(searchinfo)

        # parse args
        for arg in searchinfo.get('args', []):
            arg_match = self.VALID_ARGS_RE.match(arg)

            if arg_match:
                arg_name = arg_match.group(1)
                arg_value = arg_match.group(2)

                if arg_name == 'search_name':
                    settings['search_name'] = arg_value
                # set loglevel to DEBUG if verbose
                elif arg_name == 'verbose' and normalizeBoolean(arg_value) is True:
                    logger.setLevel(logging.DEBUG)
                    logger.debug('Log level set to DEBUG')

                settings.setdefault('configuration', {}).setdefault(arg_name, arg_value)

        # del args
        try:
            del settings['args']
        except Exception:
            pass

        # del raw_args
        try:
            del settings['raw_args']
        except Exception:
            pass

        # initialize modaction
        self.modaction = RiskModularAction(json.dumps(settings), logger)
        logger.debug(settings)

        self.modaction.validate()

        # everything went well.
        return {
            'type': 'reporting',
            'required_fields': ['*', '_*']
        }

    def handle_execute(self, metadata=None, data=None):
        metadata = {} if metadata is None else metadata
        data = '' if data is None else data

        with ModularActionTimer(self.modaction, 'main', self.modaction.start_timer):
            for num, result in enumerate(csv.DictReader(StringIO(data))):
                # set rid to row # (0->n) if unset
                result.setdefault('rid', str(num))
                self.modaction.update(result)
                self.modaction.invoke()
                self.modaction.dowork(result)

            if self.modaction.writeevents(
                    index=self.modaction.configuration.get('index', 'it_risk'),
                    source=self.modaction.search_name):
                self.modaction.message(
                    'Successfully created splunk event',
                    status='success',
                    rids=self.modaction.rids
                )
            else:
                self.modaction.message(
                    'Failed to create splunk event',
                    status='failure',
                    rids=self.modaction.rids,
                    level=logging.ERROR
                )

        # return (write back) unaltered input stream
        return (
            {'finished': metadata.get('finished', True)},
            data
        )

    def handler(self, meta, body):
        action = meta['action']

        if action == 'getinfo':
            return self.handle_getinfo(meta, body)
        elif action == 'execute':
            return self.handle_execute(meta, body)
        else:
            self.messages.error('Unknown action: %s', action)

        return meta, body


if __name__ == "__main__":
    CollectRiskHandler(handler_data=CollectRiskHandler.DATA_RAW).run()
