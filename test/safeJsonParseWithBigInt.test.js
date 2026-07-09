/*global process*/
const test = require("tape");
const { safeJsonParseWithBigInt } = require("../lib/safe-parse");

test("safeJsonParseWithBigInt: Basic functionality test", function (t) {
  // Use the specified payload string
  const payloadString = '{"userId":13123213123163776887779878}';

  const result = safeJsonParseWithBigInt(payloadString);

  t.ok(result !== null, "Parse should succeed");
  t.equal(
    typeof result.userId,
    "string",
    "Big integer should be parsed as string"
  );
  t.equal(
    result.userId,
    "13123213123163776887779878",
    "Big integer should maintain precision"
  );

  // Verify precision is maintained
  const originalNumber = 13123213123163776887779878;
  t.notEqual(
    result.userId,
    originalNumber,
    "Parsed value should not equal original number (due to precision loss)"
  );
  t.equal(
    result.userId,
    "13123213123163776887779878",
    "Parsed value should equal the string representation of original number"
  );

  t.end();
});

test("safeJsonParseWithBigInt: Boundary value test", function (t) {
  const testCases = [
    {
      name: "Maximum safe integer",
      json: '{"num":9007199254740991}',
      expectedType: "number",
      expectedValue: 9007199254740991,
    },
    {
      name: "Exceeds safe integer range",
      json: '{"num":9007199254740992}',
      expectedType: "string",
      expectedValue: "9007199254740992",
    },
    {
      name: "Very large number",
      json: '{"num":123456789012345678901234567890}',
      expectedType: "string",
      expectedValue: "123456789012345678901234567890",
    },
    {
      name: "Minimum safe integer",
      json: '{"num":-9007199254740991}',
      expectedType: "number",
      expectedValue: -9007199254740991,
    },
    {
      name: "Exceeds safe integer range (negative)",
      json: '{"num":-9007199254740992}',
      expectedType: "string",
      expectedValue: "-9007199254740992",
    },
  ];

  testCases.forEach(function (testCase) {
    const result = safeJsonParseWithBigInt(testCase.json);

    t.equal(
      typeof result.num,
      testCase.expectedType,
      `${testCase.name}: Number type should be correct`
    );
    t.same(
      result.num,
      testCase.expectedValue,
      `${testCase.name}: Number value should match`
    );
  });

  t.end();
});

test("safeJsonParseWithBigInt: Complex object test", function (t) {
  const complexJson =
    '{"user":{"id":13123213123163776887779878,"name":"test"},"normalNumber":12345,"bigNumber":987654321098765432109876543210}';

  const result = safeJsonParseWithBigInt(complexJson);

  t.ok(result !== null, "Complex object parsing should succeed");
  t.equal(
    typeof result.user.id,
    "string",
    "Big integer in nested object should be parsed as string"
  );
  t.equal(
    result.user.id,
    "13123213123163776887779878",
    "Big integer in nested object should maintain precision"
  );
  t.equal(
    typeof result.normalNumber,
    "number",
    "Normal number should remain as number type"
  );
  t.equal(
    typeof result.bigNumber,
    "string",
    "Big integer should be parsed as string"
  );
  t.equal(
    result.bigNumber,
    "987654321098765432109876543210",
    "Big integer should maintain precision"
  );

  t.end();
});

test("safeJsonParseWithBigInt: Array test", function (t) {
  const arrayJson =
    '[{"id":13123213123163776887779878,"name":"user1"},{"id":12345,"name":"user2"}]';

  const result = safeJsonParseWithBigInt(arrayJson);

  t.ok(Array.isArray(result), "Result should be an array");
  t.equal(
    typeof result[0].id,
    "string",
    "Big integer in array should be parsed as string"
  );
  t.equal(
    result[0].id,
    "13123213123163776887779878",
    "Big integer in array should maintain precision"
  );
  t.equal(
    typeof result[1].id,
    "number",
    "Normal number in array should remain as number type"
  );

  t.end();
});
