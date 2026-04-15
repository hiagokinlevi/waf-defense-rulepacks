resource "aws_wafv2_rule_group" "managed_extension_pack" {
  name     = "managed-rule-extension-pack"
  scope    = "REGIONAL"
  capacity = 100

  rule {
    name     = "advanced-sqli-patterns"
    priority = 10

    action {
      block {}
    }

    statement {
      regex_match_statement {
        regex_string = "(?i)(union[\\s\\S]*select|or\\s+1=1|information_schema|sleep\\s*\\()"

        field_to_match {
          query_string {}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 1
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "advancedSqliPatterns"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "obfuscated-xss-payloads"
    priority = 20

    action {
      block {}
    }

    statement {
      regex_match_statement {
        regex_string = "(?i)(<script|javascript:|onerror=|onload=|eval\\()"

        field_to_match {
          all_query_arguments {}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 1
          type     = "HTML_ENTITY_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "obfuscatedXssPayloads"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "suspicious-query-length"
    priority = 30

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 2048

        field_to_match {
          query_string {}
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "suspiciousQueryLength"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "managedRuleExtensionPack"
    sampled_requests_enabled   = true
  }
}
