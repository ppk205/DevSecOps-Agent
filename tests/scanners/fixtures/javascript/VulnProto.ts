import _ from "lodash";
import { Request } from "express";
export function apply(req: Request): object {
  return _.merge({}, req.body);
}
