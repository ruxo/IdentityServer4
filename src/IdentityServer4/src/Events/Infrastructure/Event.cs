// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IdentityServer4.Events.Infrastructure;

/// <summary>
/// Application event information
/// </summary>
/// <param name="Category"></param>
/// <param name="Name"></param>
/// <param name="Type"></param>
/// <param name="Id"></param>
/// <param name="Message"></param>
/// <param name="AdditionalData"></param>
public record Event(string Category, string Name, EventTypes Type, int Id, Option<object> AdditionalData);

/// <summary>
/// Models base class for events raised from IdentityServer.
/// </summary>
/// <param name="ActivityId">the per-request activity identifier.</param>
/// <param name="TimeStamp">the time stamp when the event was raised.</param>
/// <param name="ProcessId">the server process identifier.</param>
/// <param name="LocalIpAddress">the local ip address of the current request.</param>
/// <param name="RemoteIpAddress">the remote ip address of the current request.</param>
public record FullEvent(Event Message, string ActivityId, DateTime TimeStamp, int ProcessId, string LocalIpAddress, string RemoteIpAddress);