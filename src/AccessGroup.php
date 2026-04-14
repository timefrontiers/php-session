<?php

declare(strict_types=1);

namespace TimeFrontiers;

enum AccessGroup: string {
  case GUEST = 'GUEST';
  case USER = 'USER';
  case ANALYST = 'ANALYST';
  case ADVERTISER = 'ADVERTISER';
  case MODERATOR = 'MODERATOR';
  case EDITOR = 'EDITOR';
  case ADMIN = 'ADMIN';
  case DEVELOPER = 'DEVELOPER';
  case SUPERADMIN = 'SUPERADMIN';
  case OWNER = 'OWNER';
}