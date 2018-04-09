
# encoding = utf-8
# Always put this line at the beginning of this file
import award_ebadge_declare

import os
import sys
from alert_actions_base import ModularAlertBase
import modalert_award_ebadge_helper

class AlertActionWorkeraward_ebadge(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkeraward_ebadge, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("ebadge"):
            self.log_error('ebadge is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("recipient"):
            self.log_error('recipient is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_award_ebadge_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(ae.message))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e.message:
                self.log_error(msg.format(e.message))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkeraward_ebadge("TA-updatekvandlog", "award_ebadge").run(sys.argv)
    sys.exit(exitcode)
