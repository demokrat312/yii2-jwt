<?php

declare(strict_types=1);

namespace sizeg\jwt;

use DateTimeImmutable;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\CannotEncodeContent;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaimGiven;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Signature;


final class Builder implements BuilderInterface
{
    /** @var array<string, mixed> */
    private array $headers = ['typ' => 'JWT', 'alg' => null];

    /** @var array<string, mixed> */
    private array $claims = [];

    private Encoder $encoder;
    private ClaimsFormatter $claimFormatter;

    private Signer $signer;
    public Key $signerKey;

    public function __construct(Encoder $encoder, ClaimsFormatter $claimFormatter)
    {
        $this->encoder        = $encoder;
        $this->claimFormatter = $claimFormatter;
    }

    public function permittedFor(string ...$audiences): BuilderInterface
    {
        $configured = $this->claims[RegisteredClaims::AUDIENCE] ?? [];
        $toAppend   = array_diff($audiences, $configured);

        return $this->setClaim(RegisteredClaims::AUDIENCE, array_merge($configured, $toAppend));
    }

    public function expiresAt(DateTimeImmutable $expiration): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::EXPIRATION_TIME, $expiration);
    }

    public function identifiedBy(string $id): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ID, $id);
    }

    public function issuedAt(DateTimeImmutable $issuedAt): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ISSUED_AT, $issuedAt);
    }

    public function issuedBy(string $issuer): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ISSUER, $issuer);
    }

    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::NOT_BEFORE, $notBefore);
    }

    public function relatedTo(string $subject): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::SUBJECT, $subject);
    }

    /** @inheritdoc */
    public function withHeader(string $name, $value): BuilderInterface
    {
        $this->headers[$name] = $value;

        return $this;
    }

    /** @inheritdoc */
    public function withClaim(string $name, $value): BuilderInterface
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            throw RegisteredClaimGiven::forClaim($name);
        }

        return $this->setClaim($name, $value);
    }

    public function set(string $name, $value): BuilderInterface
    {
        return $this->withClaim($name, $value);
    }

    public function sign(Signer $signer, string $key) {
        $this->signer = $signer;
        $this->signerKey = InMemory::base64Encoded(random_bytes(32), $key);
    }

    /** @param mixed $value */
    private function setClaim(string $name, $value): BuilderInterface
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * @param array<string, mixed> $items
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     */
    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items)
        );
    }

    public function getToken(Signer $signer = null, Key $key = null): Plain
    {
        $signer = $this->signer;
        $key = $this->signerKey;

        $headers        = $this->headers;
        $headers['alg'] = $signer->algorithmId();

        $encodedHeaders = $this->encode($headers);
        $encodedClaims  = $this->encode($this->claimFormatter->formatClaims($this->claims));

        $signature        = $signer->sign($encodedHeaders . '.' . $encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Plain(
            new DataSet($headers, $encodedHeaders),
            new DataSet($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature)
        );
    }
}