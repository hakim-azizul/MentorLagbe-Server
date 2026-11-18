import { ObjectId } from "mongodb";

/** Reads and validates a MongoDB ObjectId from the route params. */
export function getObjectId(req, res) {
  const { id } = req.params;
  if (!/^[a-f\d]{24}$/i.test(id)) {
    res.status(400).json({ message: "Invalid id." });
    return null;
  }
  return new ObjectId(id);
}

/** Returns the list of missing keys from a request body. */
export function missingFields(body, fields) {
  return fields.filter((field) => {
    const value = body?.[field];
    return value === undefined || value === null || String(value).trim() === "";
  });
}

/**
 * `tuitionId` is stored as a string (see tApplication), but we also match the
 * ObjectId form so older/other writes keep working.
 */
export function tuitionIdIn(ids) {
  const variants = [];
  for (const id of ids) {
    variants.push(String(id));
    if (/^[a-f\d]{24}$/i.test(String(id))) variants.push(new ObjectId(String(id)));
  }
  return variants;
}

/** Standard { message } error helper. */
export function fail(res, status, message) {
  return res.status(status).json({ message });
}
