
import yaml
import os


def load_sigma_rules():

    rules = {}

    if not os.path.exists("rules"):
        return rules

    for file in os.listdir("rules"):

        if file.endswith(".yml"):

            path = os.path.join(
                "rules",
                file
            )

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:

                rule = yaml.safe_load(f)

                rules[
                    rule["title"]
                ] = rule

    return rules


def get_sigma_rule_count():

    return len(
        load_sigma_rules()
    )
