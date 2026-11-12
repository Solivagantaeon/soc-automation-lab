const createdAlerts = $input.all();
const builtAlerts = $('Build TheHive Alert').all();

return createdAlerts.flatMap((created, index) => {
  const alertId = created.json._id ?? created.json.id;

  if (!alertId) {
    throw new Error('Create an alert did not return an alert ID.');
  }

  const observables =
    builtAlerts[index]?.json?.thehive_observables ?? [];

  return observables.map(observable => ({
    json: {
      ...observable,
      alertId,
    },
  }));
});
