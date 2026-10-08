# ------------------------------------------------------------------------------
# Root Module
# ------------------------------------------------------------------------------
# Composes the individual security control modules. Each module maps to an
# SCS-C02 exam domain. Add modules here as you work through the course.
# ------------------------------------------------------------------------------

module "governance" {
  source = "./modules/governance"

  approved_regions = var.approved_regions
}
