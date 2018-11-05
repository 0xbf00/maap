#! /usr/bin/env python3

"""
appnalyser

(C) Jakob Rieck 2018

Tool to check the sandbox for an application.

Can be used to check
    - Checks for mismatch between static information indicating the
    sandbox should be enabled and the actual status of the sandbox
    during execution.
    - Checks for mismatch between static entitlements and resulting
    sandbox rules. Essentially, can an app access certain resources,
    without an entitlement?
        - microphone, camera for now.
"""

import misc.logger as logging_utils
import misc.app_utils as app_utils
from bundle.bundle import Bundle
from extern.tools import tool_named

import termcolor
from typing import List
import argparse
import abc
import subprocess
import json

logger = logging_utils.create_logger('appnalyser')

COLOR_NEUTRAL = None
COLOR_POSITIVE = "green"
COLOR_NEGATIVE = "red"


class AbstractAppChecker(abc.ABC):
    def __init__(self):
        pass

    @classmethod
    @abc.abstractmethod
    def description(cls):
        """A concise description of the function of this checker"""
        pass

    @classmethod
    @abc.abstractmethod
    def formatted_result(cls, result_dict):
        """Output formatted results from previously obtained check_app results

        Args:
            result_dict (dict): Result dictionary obtained from call to check_app.
        """
        pass

    @classmethod
    @abc.abstractmethod
    def check_app(cls, app_bundle : Bundle) -> tuple:
        """
        The check_app operation is required to return a tuple containing a success code
        and a dictionary containing the check results. The success code should indicate
        whether the operation was successful, not whether the result is negative or positive
        """
        pass


class AppSandboxStatusChecker(AbstractAppChecker):
    """Checks the status of the App Sandbox.
    In particular, checks whether the App Sandbox is
        - statically enabled and
        - dynamically active
    for an application
    """
    @classmethod
    def description(cls):
        return 'sandbox status'

    @classmethod
    def formatted_result(cls, result_dict):
        static_sandbox  = result_dict['static']
        dynamic_sandbox = result_dict['dynamic']
        if static_sandbox and dynamic_sandbox:
            return termcolor.colored("App Sandbox enabled and active.", color = COLOR_POSITIVE)
        if static_sandbox and not dynamic_sandbox:
            return termcolor.colored("App Sandbox enabled but not active.", color = COLOR_NEGATIVE)
        if not static_sandbox and not dynamic_sandbox:
            return termcolor.colored("App Sandbox not enabled and not active.", color = COLOR_NEUTRAL)
        if not static_sandbox and dynamic_sandbox:
            # This is a weird case.
            return termcolor.colored("App Sandbox not enabled but still active.", color = COLOR_NEUTRAL)

    @classmethod
    def check_app(cls, app_bundle : Bundle):
        try:
            static_sandbox = app_bundle.is_sandboxed()
            dynamic_sandbox = app_utils.init_sandbox(app_bundle, logger)
            if not static_sandbox and dynamic_sandbox:
                logger.info("App Sandbox active though not enabled for app {}".format(app_bundle.filepath))

            return (True, {
                'static': static_sandbox,
                'dynamic': dynamic_sandbox
            })
        except:
            return False, dict()


class AppSandboxCapabilitiesChecker(AbstractAppChecker):
    """Checks a subset of capabilities an application may have.
    In particular, checks whether the application has access to the microphone the webcam and, if so,
    whether the app has the appropriate entitlement."""
    @classmethod
    def description(cls):
        return "sandbox capabilities"

    @classmethod
    def formatted_result(cls, result_dict):
        results = []

        for capability in result_dict.keys():
            capability_results = result_dict[capability]
            if capability_results['static'] and capability_results['dynamic']:
                results.append(termcolor.colored('Capability \"{}\" declared and enabled.'.format(capability),
                                                 color = COLOR_NEUTRAL))
            elif not capability_results['static'] and not capability_results['dynamic']:
                results.append(termcolor.colored('Capability \"{}\" neither declared nor enabled.'.format(capability),
                                                color = COLOR_POSITIVE))
            elif not capability_results['static'] and capability_results['dynamic']:
                results.append(termcolor.colored('Capability \"{}\" not declared but enabled.'.format(capability),
                                                 color = COLOR_NEGATIVE))
            else:
                # This one's weird
                results.append(termcolor.colored('Capability \"{}\" declared but not enabled.', color = COLOR_NEUTRAL))
                # TODO: Fail hard here?

        return "\n".join(results)

    @classmethod
    def _check_capabilities_internal_static(cls, app_bundle : Bundle,
                                            entitlement_keys : List[str]):
        """Checks an applications capabilities solely statically"""
        app_entitlements = app_bundle.entitlements()
        # Check whether there is a entitlement allowing the capability
        for key in entitlement_keys:
            if app_entitlements.get(key, False):
                return True

        return False

    @classmethod
    def _check_capabilities_internal_dynamic(cls, app_bundle : Bundle,
                                             operation_name):
        """Checks whether the app sandbox allows a particular operation
        at runtime"""
        sandbox_check = tool_named("sandbox_check")

        # Initialize sandbox
        success = app_utils.init_sandbox(app_bundle, logger)
        if not success:
            return True # Unsandboxed apps may do whatever they want.

        sandbox_ruleset = app_utils.get_sandbox_rules(app_bundle)
        response = subprocess.run([sandbox_check, operation_name], input=sandbox_ruleset)

        # Capability is...
        if response.returncode == 0: # allowed
            return True
        elif response.returncode == 1: # not allowed
            return False
        else: # Some kind of error occurred.
            raise RuntimeError("Capability could not be checked.")

    @classmethod
    def _check_capabilities_internal(cls, app_bundle : Bundle,
                                     entitlement_keys : List[str],
                                     operation_name : str):
        """Checks whether an application has a certain capability,
        both according to the app's static entitlements and also
        at runtime by evaluating the applications sandboxing profile."""
        static  = cls._check_capabilities_internal_static(app_bundle, entitlement_keys)
        dynamic = cls._check_capabilities_internal_dynamic(app_bundle, operation_name)

        return static, dynamic

    @classmethod
    def check_app(cls, app_bundle : Bundle):
        try:
            result = dict()

            # Check device microphone access
            microphone_entitlements = [
                'com.apple.security.device.microphone',
                'com.apple.security.device.audio-input',
                'com.apple.security.microphone'
            ]

            microphone_operation = 'device-microphone'
            statically_allowed, dynamically_allowed = cls._check_capabilities_internal(app_bundle,
                                                                                       microphone_entitlements,
                                                                                       microphone_operation)
            result['microphone'] = {
                'static':  statically_allowed,
                'dynamic': dynamically_allowed
            }

            # Check device camera access
            camera_entitlements = [
                'com.apple.security.device.camera'
            ]
            camera_operation = 'device-camera'
            statically_allowed, dynamically_allowed = cls._check_capabilities_internal(app_bundle,
                                                                                       camera_entitlements,
                                                                                       camera_operation)
            result['camera'] = {
                'static': statically_allowed,
                'dynamic': dynamically_allowed
            }

            return True, result
        except:
            return False, dict()


def run_analyser(analyser_cls, app_bundle, produce_text = False):
    description = analyser_cls.description()

    success, local_result = analyser_cls.check_app(app_bundle)
    if not success:
        print(termcolor.colored('check \"{}\" failed. Aborting.'.format(description), COLOR_NEGATIVE))
        return False, "", dict()

    if produce_text:
        print(analyser_cls.formatted_result(local_result))

    return success, description, local_result


def analyse_app(app_path, produce_text = False):
    """
    Analyses an app to provide answers to the questions
    posed in the comment at the beginning of this file.
    Returns a dictionary containing the responses.
    """
    result = dict()

    try:
        app_bundle = Bundle.make(app_path)
    except:
        print(termcolor.colored("App processing failed. Make sure the supplied application is valid.", COLOR_NEGATIVE))
        return

    # Run all analysers
    analysers = AbstractAppChecker.__subclasses__()

    # Check if sandbox enabled
    success, key, local_result = run_analyser(AppSandboxStatusChecker, app_bundle, produce_text)
    if not success:
        return result

    result[key] = local_result
    # If the sandbox is not enabled, all other checks are mood.
    if not local_result['dynamic']:
        return result

    for analyser in analysers:
        if analyser == AppSandboxStatusChecker:
            continue

        success, key, local_result = run_analyser(analyser, app_bundle, produce_text)
        if not success:
            return result

        result[key] = local_result

    return result


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('apps', metavar='APP', type=str, nargs='+',
                        help='application(s) to investigate.')
    parser.add_argument('--textual', action='store_true',
                        help='print user friendly messages instead of JSON results.')

    arguments = parser.parse_args()
    results = []

    for app in arguments.apps:
        results.append(analyse_app(app, arguments.textual))

    if not arguments.textual:
        print(json.dumps(results))

if __name__ == "__main__":
    main()