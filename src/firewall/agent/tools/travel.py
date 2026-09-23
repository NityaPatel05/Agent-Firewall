"""Travel tools."""

from __future__ import annotations

from typing import Any

from firewall.agent.tools._base import ToolError, dec, impl, num
from firewall.agent.world import MockWorld


@impl("travel")
def search_hotels(world: MockWorld, city: str, max_price: Any = None) -> list[dict]:
    cap = dec(max_price) if max_price is not None else None
    return [{"id": h.id, "name": h.name, "city": h.city, "price": num(h.price), "description": h.description}
            for h in world.travel.hotels
            if h.city.lower() == city.lower() and (cap is None or h.price <= cap)]


@impl("travel")
def get_hotel_reviews(world: MockWorld, hotel_id: str) -> dict[str, Any]:
    for h in world.travel.hotels:
        if h.id == hotel_id:
            return {"hotel": h.name, "reviews": list(h.reviews)}
    raise ToolError(f"hotel {hotel_id} not found")


@impl("travel")
def search_flights(world: MockWorld, origin: str, dest: str, date: str | None = None) -> list[dict]:
    return [{"id": f.id, "origin": f.origin, "dest": f.dest, "date": f.date, "price": num(f.price),
             "airline": f.airline}
            for f in world.travel.flights
            if f.origin.lower() == origin.lower() and f.dest.lower() == dest.lower()
            and (date is None or f.date == str(date)[:10])]


@impl("travel")
def book_hotel(world: MockWorld, hotel_id: str, check_in: str, check_out: str) -> dict[str, Any]:
    hotel = next((h for h in world.travel.hotels if h.id == hotel_id), None)
    if hotel is None:
        raise ToolError(f"hotel {hotel_id} not found")
    booking = {"type": "hotel", "id": hotel_id, "check_in": check_in, "check_out": check_out,
               "price": num(hotel.price)}
    world.travel.bookings.append(booking)
    return {"status": "booked", **booking}


@impl("travel")
def book_flight(world: MockWorld, flight_id: str) -> dict[str, Any]:
    flight = next((f for f in world.travel.flights if f.id == flight_id), None)
    if flight is None:
        raise ToolError(f"flight {flight_id} not found")
    booking = {"type": "flight", "id": flight_id, "price": num(flight.price)}
    world.travel.bookings.append(booking)
    return {"status": "booked", **booking}
