<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * EXTENSION-TYPE — the system/type:validate handler. Validates an entity against a
 * registered §2 type definition: every required (non-optional) field present, and
 * any unevaluated (extra) fields reported. Returns a system/type/validate-result
 * `{valid, violations?, unevaluated_fields?}`. The `type` category is EXTENSION
 * (auto-skipped under --profile core); the structural checks are the floor.
 */
final class TypeHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        if ($operation !== 'validate') {
            return Outcome::err(501, 'unsupported_operation', $operation);
        }
        $req = $ctx->params();
        if ($req === null) {
            return Outcome::err(400, 'invalid_params', 'validate requires a params entity');
        }
        $subject = $req->entityField('entity');
        if ($subject === null) {
            return Outcome::err(400, 'unexpected_params', 'validate-request missing entity');
        }
        $typeName = $req->text('type_path') ?? $subject->type;
        $typeDef = $this->peer->store->getAt($this->peer->abs("system/type/{$typeName}"));
        if ($typeDef === null) {
            $vs = [Ecf::map('kind', 'unknown_type', 'field', $typeName,
                'message', "no registered type definition for {$typeName}")];
            return Outcome::ok(Entity::make('system/type/validate-result',
                Ecf::map('valid', false, 'violations', $vs)));
        }
        $fields = $typeDef->mapField('fields');
        $subjData = Ecf::asMap($subject->rawData());
        $violations = [];
        $unevaluated = [];
        $declared = [];
        if ($fields !== null) {
            foreach ($fields->entries() as [$fk, $fv]) {
                if (!\is_string($fk)) {
                    continue;
                }
                $declared[$fk] = true;
                $spec = Ecf::asMap($fv);
                $optional = $spec !== null && Ecf::isTrue($spec->get('optional'));
                $present = $subjData !== null && $subjData->hasTextKey($fk);
                if (!$optional && !$present) {
                    $violations[] = Ecf::map('kind', 'missing_required_field', 'field', $fk,
                        'message', 'required field absent');
                }
            }
        }
        if ($subjData !== null) {
            foreach ($subjData->entries() as [$sk]) {
                if (\is_string($sk) && !isset($declared[$sk])) {
                    $unevaluated[] = $sk;
                }
            }
        }
        $valid = $violations === [];
        $result = new EcfMap();
        $result->put('valid', $valid);
        if ($violations !== []) {
            $result->put('violations', \array_values($violations));
        }
        if ($unevaluated !== []) {
            $result->put('unevaluated_fields', \array_values($unevaluated));
        }
        return Outcome::ok(Entity::make('system/type/validate-result', $result));
    }
}
