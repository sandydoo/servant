{-# LANGUAGE CPP #-}

module Servant.Auth.JWT where

import qualified Crypto.JWT as Jose
import Data.Aeson
  ( FromJSON,
    Result (..),
    ToJSON,
    Value (..),
    fromJSON,
    parseJSON,
    toJSON,
    withObject,
  )
import Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import qualified Data.Map.Strict as M
import qualified Data.Set as S

data ClaimsSet = ClaimsSet {jwtClaims :: Jose.ClaimsSet, jwtUnregisteredClaims :: M.Map T.Text Value }

instance Jose.HasClaimsSet ClaimsSet where
  claimsSet f s = fmap (\a' -> s {jwtClaims = a'}) (f $ jwtClaims s)

instance FromJSON ClaimsSet where
  parseJSON = withObject "ClaimsSet" $ \o ->
    ClaimsSet <$> parseJSON (Object o) <*> pure (filterUnregistered . fromKeyMap $ o)
    where
      filterUnregistered :: M.Map T.Text Value -> M.Map T.Text Value
      filterUnregistered m =
#if MIN_VERSION_containers(0,5,8)
        m `M.withoutKeys` registeredClaims
#else
        m `M.difference` M.fromSet (const ()) registeredClaims
#endif
      registeredClaims :: S.Set T.Text
      registeredClaims = S.fromDistinctAscList
        [ "aud"
        , "exp"
        , "iat"
        , "iss"
        , "jti"
        , "nbf"
        , "sub"
        ]

instance ToJSON ClaimsSet where
  toJSON (ClaimsSet cs d) = case toJSON cs of
    Object o -> Object (o <> toKeyMap d)
    _ -> error "impossible"

class FromJWT a where
  decodeJWT :: (FromJSON a) => ClaimsSet -> Either T.Text a
  default decodeJWT :: FromJSON a => ClaimsSet -> Either T.Text a
  decodeJWT m = 
    case M.lookup "dat" (jwtUnregisteredClaims m) of
      Nothing -> Left "Missing dat claim"
      Just v -> case fromJSON v of
        Error e -> Left $ T.pack e
        Success a -> Right a

class ToJWT a where
  encodeJWT :: (ToJSON a) => a -> ClaimsSet
  default encodeJWT :: (ToJSON a) => a -> ClaimsSet
  encodeJWT a =
    ClaimsSet {jwtClaims = Jose.emptyClaimsSet, jwtUnregisteredClaims = M.fromList [("dat", toJSON a)]}

fromKeyMap :: KM.KeyMap Value -> M.Map T.Text Value
fromKeyMap = M.mapKeysMonotonic Key.toText . KM.toMap

toKeyMap :: M.Map T.Text Value -> KM.KeyMap Value
toKeyMap = KM.fromMap . M.mapKeysMonotonic Key.fromText
